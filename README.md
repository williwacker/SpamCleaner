# SpamCleaner

Application for cleaning up your email account from spam mail based on a given list of email addresses.
In order to easily enhance your blacklist you can create a folder "Blacklist" in your email account. If you add this folder into your \<filename\>.ini folder list then every email address in this folder gets added to the appropriate blacklist.

## Installation

- download zip and unpack

- create the config file <filename>.ini based on my_account.ini.sample

  - this config file can have a common blacklist filename in the DEFAULT part, as well as individual blacklist filenames for every account

  - required parameters are HOST, USERNAME, PASSWORD, FOLDER. If one of these parameters is missing the account will be ignored.

## PRE-REQUISITE

```
pip3 install imapclient
```

## EXECUTION

```
python3 spam_cleaner.py -c <filename>.ini
```
