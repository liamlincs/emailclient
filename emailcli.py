import os
import configparser
import logging
import argparse
import poplib
import threading
import traceback
from imapclient import IMAPClient
from email import message_from_bytes

import socket
import socks

DEFAULT_TIMEOUT = 30

# Configuration file
CONFIG_FILE = 'config.ini'

# Read configuration file
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

# Get configuration parameters
max_emails = int(config.get('settings', 'max_emails'))
email_output_dir = config.get('settings', 'email_output_dir')
proxy = config.get('settings', 'proxy')

# Create a command line argument parser
parser = argparse.ArgumentParser(description="Email client for POP3 and IMAP4")
parser.add_argument('--server', help='Email server address')
parser.add_argument('--user', help='Email account username')
parser.add_argument('--password', help='Email account password')
parser.add_argument('--protocol', help='Email protocol (POP3 or IMAP4)')

# Parse command line arguments
args = parser.parse_args()

# Configure logs
logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[logging.StreamHandler(),
                                  logging.FileHandler('emailcli.log', encoding='utf-8')])

class EmailClient:
    def __init__(self, server, username, password, protocol='POP3', proxy=None):
        self.server = server
        self.username = username
        self.password = password
        self.protocol = protocol
        if proxy:
            proxy_protocol, proxy_host, proxy_port = proxy.split(':')
            if proxy_protocol.find('sock') != -1:
                proxy_type = socks.SOCKS5
            else:
                proxy_type = socks.HTTP
            proxy_host = proxy_host.replace('//', '')
            socks.set_default_proxy(proxy_type, proxy_host, int(proxy_port))
            socket.socket = socks.socksocket

    def _create_pop3_connection(self):
        if self.protocol.find('s') != -1:
            if self.protocol.find(':') != -1:
                port = int(self.protocol.split(':')[1])
            else:
                port = 995
            pop3_server = poplib.POP3_SSL(self.server, port, timeout=DEFAULT_TIMEOUT)
        else:
            if self.protocol.find(':') != -1:
                port = int(self.protocol.split(':')[1])
            else:
                port = 110
            pop3_server = poplib.POP3(self.server, timeout=DEFAULT_TIMEOUT)

        return pop3_server

    def _create_imap4_connection(self):
        if self.protocol.find('s') != -1:
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
        imap4_server = IMAPClient(self.server, port, ssl = bSSL, timeout=DEFAULT_TIMEOUT)
        
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
            logging.error(traceback.format_exc())
            raise

    def fetch_emails(self):
        if self.protocol.find('POP3') != -1:
            return self._fetch_pop3_emails()
        elif self.protocol.find('IMAP4') != -1:
            return self._fetch_imap4_emails()

    def _fetch_pop3_emails(self):
        try:
            downloaded_cnt = 0
            email_count, _ = self.mailbox.stat()

            # Read the acquired Message-ID from the file
            mid_downloaded_path = os.path.join(email_output_dir, self.protocol, self.username)
            mid_downloaded_file = os.path.join(mid_downloaded_path, "INBOX_mid_downloaded.txt")
            if os.path.exists(mid_downloaded_file):
                with open(mid_downloaded_file, 'r') as f:
                    fetched_ids = f.read().splitlines()
            else:
                fetched_ids = []

            for email_id in range(1, email_count + 1):
                response, lines, _ = self.mailbox.retr(email_id)
                raw_msg = b'\r\n'.join(lines)
                msg = message_from_bytes(raw_msg)
                message_id = msg['Message-ID']

                # Check if the Message-ID already exists in the retrieved emails
                if message_id not in fetched_ids:

                    # Create a file name for the email
                    safe_message_id = message_id.replace('<', '').replace('>', '')

                    email_file = os.path.join(email_output_dir, self.protocol, self.username, "INBOX", f"{safe_message_id}.eml")
                    os.makedirs(os.path.dirname(email_file), exist_ok=True)
                    with open(email_file, 'wb') as f:
                        f.write(raw_msg)
                    logging.info(f"Saved to {safe_message_id}")

                    # Add the new Message-ID to the list of already obtained Message-IDs and update the file
                    fetched_ids.append(message_id)
                    with open(mid_downloaded_file, 'a') as f:
                        f.write(f"{message_id}\n")
                    downloaded_cnt += 1
                    if downloaded_cnt >= max_emails:
                        logging.info(f"Reach maximum download limit {downloaded_cnt}")
                        break
                else:
                    logging.info(f"Skipped mid {message_id} in INBOX")
        except:
            logging.error(traceback.format_exc())
            raise

    def _fetch_imap4_emails(self):
        try:
            listfolders = self.mailbox.list_folders()
            folders = []
            for folder in listfolders:
                itemfolder = folder[2]
                if itemfolder.lower().find('sent') != -1 or itemfolder.lower().find('已发送') != -1:
                    folders.insert(0, itemfolder)
                else:
                    folders.append(itemfolder)

            mid_downloaded_path = os.path.join(email_output_dir, self.protocol, self.username)

            for folder in folders:
                try:
                    downloaded_cnt = 0
                    self.mailbox.select_folder(folder)
                    email_ids = self.mailbox.search()

                    # Read the acquired Message-ID from the file
                    mid_downloaded_file = os.path.join(mid_downloaded_path, f"{folder}_mid_downloaded.txt")
                    if os.path.exists(mid_downloaded_file):
                        with open(mid_downloaded_file, 'r') as f:
                            fetched_ids = f.read().splitlines()
                    else:
                        fetched_ids = []

                    for email_id in email_ids:
                        msg_data = self.mailbox.fetch([email_id], ['RFC822'])
                        raw_msg = msg_data[email_id][b'RFC822']
                        msg = message_from_bytes(raw_msg)
                        message_id = msg['Message-ID']

                        # Check if the Message-ID already exists in the retrieved emails
                        if message_id not in fetched_ids:

                            # Create a file name for the email
                            safe_message_id = message_id.replace('<', '').replace('>', '')

                            # Write email data to .eml file
                            email_file = os.path.join(email_output_dir, self.protocol, self.username, folder, f"{safe_message_id}.eml")
                            os.makedirs(os.path.dirname(email_file), exist_ok=True)
                            with open(email_file, 'wb') as f:
                                f.write(raw_msg)

                            logging.info(f"Saved to {email_file}")

                            # Add the new Message-ID to the list of already obtained Message-IDs and update the file
                            fetched_ids.append(message_id)
                            with open(mid_downloaded_file, 'a') as f:
                                f.write(f"{message_id}\n")
                            downloaded_cnt += 1
                            if downloaded_cnt >= max_emails:
                                logging.info(f"Reach maximum download limit {downloaded_cnt}")
                                break
                        else:
                            logging.info(f"Skipped mid {message_id} in {folder}")
                except:
                    logging.error(traceback.format_exc())
                    continue
        except:
            logging.error(traceback.format_exc())
            raise

    def close(self):
        try:
            if self.protocol.find('POP3') != -1:
                self.mailbox.quit()
            elif self.protocol.find('IMAP4') != -1:
                self.mailbox.logout()
        except:
            logging.error(traceback.format_exc())

def process_email_account(email_client):
    try:
        email_client.connect()
        email_client.fetch_emails()
    finally:
        email_client.close()

def read_accounts_from_file(file_path):
    email_clients = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                server, username, password, protocol = line.strip().split(',')
                email_clients.append(EmailClient(server, username, password, protocol.upper()))
    except:
        logging.error(traceback.format_exc())
    return email_clients

def main():
    email_clients = []
    
    # If all necessary information is provided through command line arguments, process the account directly
    if args.server and args.user and args.password and args.protocol:
        email_clients.append(EmailClient(args.server, args.user, args.password, args.protocol))
    # Otherwise, read account information from the file and process it.
    else:
        account_file_path = 'accounts.txt'
        email_clients = read_accounts_from_file(account_file_path)

    threads = []
    for email_client in email_clients:
        thread = threading.Thread(target=process_email_account, args=(email_client,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

if __name__ == '__main__':
    main()
