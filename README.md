# SpamCleaner

Application for cleaning up your email account from spam mail based on a given list of email addresses.
In order to easily enhance your blacklist you can create a folder "Blacklist" in your email account. If you add this folder into your \<filename\>.ini folder list then every email address in this folder gets added to the appropriate blacklist.
For emails going into the Spam folder by mistake you define can the addresses in the whitelist file and they will get moved into the Inbox

## Installation

- download zip and unpack

- create the config file <filename>.ini based on my_account.ini.sample

  - this config file can have a common blacklist and whitelist filename in the DEFAULT part, as well as an individual blacklist/whitelist filenames for every account

  - required parameters for blacklisting are HOST, USERNAME, PASSWORD, FOLDER. If one of these parameters is missing the account will be ignored.
  - required parameters for whitelisting are HOST, USERNAME, PASSWORD, FOLDER, INBOX. If one of these parameters is missing the account will be ignored.

## PRE-REQUISITE

```
pip3 install imapclient
```

## EXECUTION

```
python3 spam_cleaner.py -c <filename>.ini
```
