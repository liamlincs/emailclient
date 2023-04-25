# Email Client for POP3 and IMAP4

This email client is a command-line application that supports both POP3 and IMAP4 protocols to fetch and store emails from your email server. It is designed to handle multiple email accounts and allows for easy configuration and customization.

## Features

- Supports both POP3 and IMAP4 protocols
- Can handle multiple email accounts from different providers
- Downloads emails and stores them as .eml files
- Uses Message-ID to avoid downloading duplicate emails
- Supports logging in using an accounts.txt file or command-line arguments
- Can be easily configured with a configuration file
- Supports SSL/TLS connections for secure email fetching

## Installation

1. Clone this repository:

   ```
   git clone https://github.com/liamlincs/email-client.git
   ```

2. Change to the project directory:

   ```
   cd email-client
   ```

3. Install the required dependencies:

   ```
   pip install -r requirements.txt
   ```

## Usage

### Using the accounts.txt file

Create a file named `accounts.txt` in the project directory with the following format:

```
server1.example.com,user1,password1,POP3
server2.example.com,user2,password2,IMAP4
...
```

Each line represents an email account with the server address, username, password, and protocol (POP3 or IMAP4) separated by commas.

### Using command-line arguments

You can also provide the email account information directly as command-line arguments:

```
python3 email_client.py --server server.example.com --user username --password your_password --protocol POP3
```

### Downloading emails

The email client will download emails from the specified email accounts and store them as .eml files in a directory named after the email account.

The client uses the Message-ID header to avoid downloading duplicate emails. The Message-IDs of the downloaded emails are saved in a text file to keep track of already fetched emails.

## Configuration

The email client can be configured using a configuration file named `config.ini`. This file allows you to customize various settings, such as the the number of emails to fetch, and more.

## Contributing

Feel free to open issues or submit pull requests if you find any bugs or want to contribute to the project. We welcome any feedback and suggestions.

## License

This project is licensed under the MIT License.