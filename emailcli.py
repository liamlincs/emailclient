import os
import configparser
import argparse
import poplib
import threading
import traceback
import schedule
import time
import socket
import socks
import base64
import logging
import datetime
import ssl
from logging.handlers import RotatingFileHandler
from imapclient import IMAPClient
from email import message_from_bytes
from cryptography.fernet import Fernet

DEFAULT_TIMEOUT = 30
# Configuration file
CONFIG_FILE = 'config.ini'

# Read configuration file
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

# Get configuration parameters
schedule_minutes = int(config.get('settings', 'schedule_minutes'))
max_emails = int(config.get('settings', 'max_emails'))
email_output_dir = config.get('settings', 'email_output_dir')
email_export_dir = config.get('settings', 'email_export_dir')
proxy = config.get('settings', 'proxy')
debugFlag = config.getboolean('settings', 'debug')

# Create a command line argument parser
parser = argparse.ArgumentParser(description="Email client for POP3 and IMAP4")
parser.add_argument('--server', help='Email server address')
parser.add_argument('--user', help='Email account username')
parser.add_argument('--password', help='Email account password')
parser.add_argument('--protocol', help='Email protocol (POP3 or IMAP4)')

# Parse command line arguments
args = parser.parse_args()

# Configure logs
logger = logging.getLogger('emailcli_logger')
logger.setLevel(logging.DEBUG)

os.makedirs("logs", exist_ok=True)
info_handler = RotatingFileHandler('logs/info_emailcli.log', maxBytes=1024*1024*10, backupCount=10)
info_handler.setLevel(logging.INFO)

debug_handler = RotatingFileHandler('logs/debug_emailcli.log', maxBytes=1024*1024*10, backupCount=50)
debug_handler.setLevel(logging.DEBUG)

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s (line: %(lineno)d)')
info_handler.setFormatter(formatter)
debug_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

logger.addHandler(info_handler)
logger.addHandler(debug_handler)
logger.addHandler(stream_handler)

class EmailClient:
    def __init__(self, server, username, password, protocol='POP3', proxy=None):
        self.server = server
        self.username = username
        self.password = password
        self.protocol = protocol
        if proxy:
            proxy_protocol, proxy_host, proxy_port = proxy.split(':')
            if proxy_protocol.find('sock') != -1:
                proxy_type = socks.PROXY_TYPE_SOCKS5
            else:
                proxy_type = socks.PROXY_TYPE_HTTP
            proxy_host = proxy_host.replace('//', '')
            
            # socks.setdefaultproxy(proxy_type, proxy_host, int(proxy_port))
            socks.set_default_proxy(proxy_type, proxy_host, int(proxy_port))
            # socks.wrap_module(poplib)
            # socket.socket = socks.socksocket

    def _create_pop3_connection(self):
        if self.protocol.find('S') != -1:
            if self.protocol.find(':') != -1:
                port = int(self.protocol.split(':')[1])
            else:
                port = 995

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
            pop3_server = poplib.POP3_SSL(self.server, port, context=ctx, timeout=DEFAULT_TIMEOUT)
            # sock = socks.socksocket()
            # sock.connect(self.server, port)
            # ssl_sock = ssl.wrap_socket(sock)
            # pop3_server = poplib.POP3_SSL(ssl_sock)
        else:
            if self.protocol.find(':') != -1:
                port = int(self.protocol.split(':')[1])
            else:
                port = 110
            
            pop3_server = poplib.POP3(self.server, timeout=DEFAULT_TIMEOUT)

        return pop3_server

    def _create_imap4_connection(self):
        if self.protocol.find('S') != -1:
            if self.protocol.find(':') != -1:
                port = int(self.protocol.split(':')[1])
            else:
                port = 993
            bSSL = True
        else:
            if self.protocol.find(':') != -1:
                port = int(self.protocol.split(':')[1])
            else:
                port = 143
            bSSL = False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ctx.set_ciphers('ALL')
        imap4_server = IMAPClient(self.server, port, ssl = bSSL, ssl_context=ctx, timeout=DEFAULT_TIMEOUT)
        
        return imap4_server

    def connect(self):
        try:
            if self.protocol.find('POP3') != -1:
                self.mailbox = self._create_pop3_connection()
                self.mailbox.user(self.username)
                self.mailbox.pass_(self.password)
            elif self.protocol.find('IMAP4') != -1:                
                self.mailbox = self._create_imap4_connection()
                self.mailbox.login(self.username, self.password)
                if self.server == 'imap.163.com':
                    self.mailbox.id_({"name": "IMAPClient", "version": "2.1.0"})
            else:
                raise ValueError("Invalid protocol. Supported protocols are 'POP3' and 'IMAP4'.")
        except:
            logger.info(f"[{self.username}] {traceback.format_exc()}")
            raise

    def fetch_emails(self):
        if self.protocol.find('POP3') != -1:
            return self._fetch_pop3_emails()
        elif self.protocol.find('IMAP4') != -1:
            return self._fetch_imap4_emails()

    def _fetch_pop3_emails(self):
        try:
            os.makedirs(os.path.join(email_output_dir, f"{datetime.datetime.now().strftime('%Y%m%d')}", self.username), exist_ok=True)

            downloaded_cnt = 0
            neterr_cnt = 0
            email_count, _ = self.mailbox.stat()
            logger.info(f"[{self.username}] has {email_count} messages in INBOX")

            # Read the acquired Message-ID from the file
            mid_downloaded_path = os.path.join(email_output_dir, 'cache', self.username)
            mid_downloaded_file = os.path.join(mid_downloaded_path, "INBOX_mid_downloaded.txt")
            if os.path.exists(mid_downloaded_file):
                with open(mid_downloaded_file, 'r') as f:
                    fetched_ids = f.read().splitlines()
            else:
                fetched_ids = []
                os.makedirs(os.path.dirname(mid_downloaded_file), exist_ok=True)

            for email_id in range(email_count, 0, -1):
                try:
                    response, lines, _ = self.mailbox.retr(email_id)
                    raw_msg = b'\r\n'.join(lines)
                    msg = message_from_bytes(raw_msg)
                    message_id = msg['Message-ID']
                    if message_id is None:
                        message_id = self.mailbox.uidl(email_id).decode().split(' ')[2]

                    # Check if the Message-ID already exists in the retrieved emails
                    if message_id not in fetched_ids:

                        # Create a file name for the email
                        
                        safe_message_id = message_id.replace('<', '').replace('>', '')

                        email_file = os.path.join(email_output_dir, f"{datetime.datetime.now().strftime('%Y%m%d')}", self.username, "INBOX", f"{safe_message_id}.eml")
                        os.makedirs(os.path.dirname(email_file), exist_ok=True)
                        with open(email_file, 'wb') as f:
                            f.write(raw_msg)
                        logger.info(f"Saved to f'{email_file}'")

                        if email_export_dir != '':
                            export_email_file = os.path.join(email_export_dir, self.username, "INBOX", f"{safe_message_id}.eml")
                            os.makedirs(os.path.dirname(export_email_file), exist_ok=True)
                            with open(export_email_file, 'wb') as f:
                                f.write(raw_msg)
                            logger.info(f"Export to f'{export_email_file}'")

                        # Add the new Message-ID to the list of already obtained Message-IDs and update the file
                        fetched_ids.append(message_id)
                        with open(mid_downloaded_file, 'a') as f:
                            f.write(f"{message_id}\n")
                        downloaded_cnt += 1
                        if downloaded_cnt >= max_emails:
                            logger.info(f"[{self.username}] Reach maximum download limit {downloaded_cnt}")
                            break
                    else:
                        logger.debug(f"[{self.username}] Skipped mid {message_id} in INBOX")
                except:
                    logger.error(f"[{self.username}] {traceback.format_exc()}")
                    neterr_cnt += 1
                    if neterr_cnt >= 5:
                        break
        except:
            logger.error(f"[{self.username}] {traceback.format_exc()}")
            raise

    def _fetch_imap4_emails(self):
        try:
            os.makedirs(os.path.join(email_output_dir, f"{datetime.datetime.now().strftime('%Y%m%d')}", self.username), exist_ok=True)

            listfolders = self.mailbox.list_folders()
            folders = []
            for folder in listfolders:
                itemfolder = folder[2]
                if itemfolder.lower().find('sent') != -1 or itemfolder.lower().find('已发送') != -1:
                    folders.insert(0, itemfolder)
                else:
                    folders.append(itemfolder)

            mid_downloaded_path = os.path.join(email_output_dir, 'cache', self.username)

            for folder in folders:
                try:
                    downloaded_cnt = 0
                    self.mailbox.select_folder(folder)
                    email_ids = self.mailbox.search()
                    email_count = len(email_ids)
                    logger.info(f"[{self.username}] has {email_count} messages in {folder}")

                    # Read the acquired Message-ID from the file
                    mid_downloaded_file = os.path.join(mid_downloaded_path, f"{folder}_mid_downloaded.txt")
                    if os.path.exists(mid_downloaded_file):
                        with open(mid_downloaded_file, 'r') as f:
                            fetched_ids = f.read().splitlines()
                    else:
                        fetched_ids = []
                        os.makedirs(os.path.dirname(mid_downloaded_file), exist_ok=True)

                    email_ids.reverse()

                    for email_id in email_ids:
                        msg_data = self.mailbox.fetch([email_id], ['RFC822'])
                        raw_msg = msg_data[email_id][b'RFC822']
                        msg = message_from_bytes(raw_msg)
                        message_id = msg['Message-ID']
                        if message_id is None:
                            message_id = str(msg_data[email_id][b'SEQ'])

                        # Check if the Message-ID already exists in the retrieved emails
                        if message_id not in fetched_ids:

                            # Create a file name for the email
                            safe_message_id = message_id.replace('<', '').replace('>', '')

                            # Write email data to .eml file
                            email_file = os.path.join(email_output_dir, f"{datetime.datetime.now().strftime('%Y%m%d')}", self.username, folder, f"{safe_message_id}.eml")
                            os.makedirs(os.path.dirname(email_file), exist_ok=True)
                            with open(email_file, 'wb') as f:
                                f.write(raw_msg)
                            logger.info(f"Saved to {email_file}")

                            if email_export_dir != '':
                                export_email_file = os.path.join(email_export_dir, self.username, folder, f"{safe_message_id}.eml")
                                os.makedirs(os.path.dirname(export_email_file), exist_ok=True)
                                with open(export_email_file, 'wb') as f:
                                    f.write(raw_msg)
                                logger.info(f"Export to f'{export_email_file}'")

                            # Add the new Message-ID to the list of already obtained Message-IDs and update the file
                            fetched_ids.append(message_id)
                            with open(mid_downloaded_file, 'a') as f:
                                f.write(f"{message_id}\n")
                            downloaded_cnt += 1
                            if downloaded_cnt >= max_emails:
                                logger.debug(f"[{self.username}] Reach maximum download limit {downloaded_cnt}")
                                break
                        else:
                            logger.debug(f"[{self.username}] Skipped mid {message_id} in {folder}")
                except:
                    logger.error(f"[{self.username}] {traceback.format_exc()}")
                    continue
        except:
            logger.error(f"[{self.username}] {traceback.format_exc()}")
            raise

    def close(self):
        try:
            if self.protocol.find('POP3') != -1:
                self.mailbox.quit()
            elif self.protocol.find('IMAP4') != -1:
                self.mailbox.logout()
        except:
            logger.error(f"[{self.username}] {traceback.format_exc()}")

def process_email_account(email_client):
    try:
        email_client.connect()
        email_client.fetch_emails()
    finally:
        email_client.close()

def read_accounts_from_file_debugmode(file_path):
    email_clients = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                values = line.strip().split(',')
                if len(values) == 5:
                    server, username, password, protocol, proxyline = values
                    email_clients.append(EmailClient(server, username, password, protocol.upper(), proxyline))
                else:
                    server, username, password, protocol = values
                    email_clients.append(EmailClient(server, username, password, protocol.upper(), proxy))
    except:
        logger.error(traceback.format_exc())
    return email_clients

def read_accounts_from_file_prodmode(input_file):
    email_clients = []
    try:
        sn = open('key.key', 'rb').read()
    except:
        sn = 'MDZuaGNwNkxoY3BqUWpmWG1ndzJlTllKOUFzZHNRWHBmZl95SzExZXc0RT0='
    fernet = Fernet(base64.b64decode(sn))

    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = fernet.decrypt(encrypted_data)
    
    try:
        stringBuf = str(decrypted_data, encoding='utf-8')
        for line in stringBuf.splitlines():
            values = line.strip().split(',')
            if len(values) == 5:
                server, username, password, protocol, proxyline = values
                email_clients.append(EmailClient(str(server), username, password, protocol.upper(), proxyline))
            else:
                server, username, password, protocol = values
                email_clients.append(EmailClient(str(server), username, password, protocol.upper(), proxy))
    except:
        logger.error(traceback.format_exc())
    return email_clients

def main():
    email_clients = []
    
    # If all necessary information is provided through command line arguments, process the account directly
    if args.server and args.user and args.password and args.protocol:
        email_clients.append(EmailClient(args.server, args.user, args.password, args.protocol.upper(), proxy))
    # Otherwise, read account information from the file and process it.
    elif debugFlag:
        account_file_path = 'accounts.txt'
        email_clients = read_accounts_from_file_debugmode(account_file_path)
    else:
        account_file_path = 'encrypted_acc.txt'
        email_clients = read_accounts_from_file_prodmode(account_file_path)

    threads = []
    for email_client in email_clients:
        thread = threading.Thread(target=process_email_account, args=(email_client,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

if __name__ == '__main__':
    main()
    schedule.every(schedule_minutes).minutes.do(main)
    while True:
        schedule.run_pending()
        time.sleep(1)
