import argparse
import codecs
import configparser
import email
import logging
import os
import re
import ssl
import sys
from datetime import datetime
from email.header import decode_header
from pathlib import Path

from fuzzywuzzy import fuzz
from imapclient import IMAPClient

__version__ = '1.1.0'

# Enable logging
logpath = os.path.join(
    os.path.dirname(__file__),
    'log'
)
logfile = os.path.join(
    logpath,
    os.path.splitext(os.path.basename(__file__))[0]+".log"
)
if not os.path.exists(logpath):
    os.makedirs(logpath)
logging.basicConfig(format='%(asctime)s %(levelname)s [%(filename)s:%(lineno)s] %(message)s',
                    filename=logfile, level=logging.INFO)
logger = logging.getLogger(__name__)


class SpamCleaner():

    def __init__(self):
        logger.info(__file__+' started')
        args = self.__get_cli_arguments__()
        fname = os.path.join(
            os.path.dirname(__file__),
            'config',
            args.configfile[0],
        )
        if os.path.isfile(fname):
            self.prefs = self.__read_configuration__(fname)
        else:
            logger.error(
                'No config file provided or config file not found. Use "%s -c <config.ini>"',
                os.path.basename(__file__),
            )
            sys.exit(1)
        for account in self.prefs:
            if account != 'DEFAULT':
                self.moveSpam(account)
                self.deleteSpam(account)

    def get_black_or_white_list(self, list_file):
        if list_file and Path(list_file).is_file():
            return codecs.open(list_file, 'r', 'utf-8').read().splitlines()

    def append_blacklist(self, blacklist_file, address):
        blacklist = self.get_black_or_white_list(blacklist_file)
        if blacklist:
            found = False
            for line in blacklist:
                if line in address:
                    found = True
                    break
            if not found:
                blacklist.append(address)
                blacklist = sorted(list(set(blacklist)))
                with codecs.open(blacklist_file, 'w', 'utf-8') as bl:
                    bl.write('\n'.join(blacklist))

    def __get_cli_arguments__(self):
        parser = argparse.ArgumentParser(description='Email Spam Cleaner')
        parser.add_argument('-c', '--configfile',
                            nargs=1,
                            help='Spam Cleaner config file'
                            )
        parser.add_argument('-v', '--version',
                            action='version', version=__version__,
                            help='Print the program version'
                            )
        return parser.parse_args()

    # read configuration from the configuration file and prepare a preferences dict
    def __read_configuration__(self, filename):
        cfg = configparser.ConfigParser()
        cfg.read(filename)
        preferences = {}
        for sectionname, *_ in cfg.items():
            preferences[sectionname] = {}
            for name, value in cfg.items(sectionname):
                preferences[sectionname][name] = value
        return preferences

    def get_ip(self, email_message):
        headers = email_message._headers
        res = list(
            filter(lambda sub, ele='Received': ele in sub[0], headers))[0][1]
        m = re.findall("from .*\(\[(\d+.\d+.\d+.\d+)\]\)", res)
        if m:
            return m[0]

    def get_from(self, email_message):
        email_from = decode_header(
            email_message.get('From'))[0]
        if isinstance(email_from[0], bytes) and not email_from[1]:
            return
        if isinstance(email_from[0], bytes) and email_from[1]:
            email_from = email_from[0].decode(
                email_from[1])
        elif isinstance(email_from[0], str):
            email_from = email_from[0]
        return email_from

    def get_subject(self, email_message):
        encoded_str = decode_header(email_message.get('Subject'))
        subject = ''
        for s_tuple in encoded_str:
            if s_tuple[1]:
                try:
                    subject += s_tuple[0].decode(encoding=s_tuple[1])
                except:
                    subject += s_tuple[0].decode()
            else:
                try:
                    subject += s_tuple[0].decode()
                except:
                    subject += s_tuple[0]
        return subject

    def deleteSpam(self, account):
        diff = set(['host', 'username', 'password', 'folder']
                   ).difference(set(self.prefs[account]))
        if diff:
            logger.error(
                'Missing parameter(s) %s in ini file for %s',
                diff,
                account,
            )
            return
        HOST = self.prefs[account]['host']
        USERNAME = self.prefs[account]['username']
        PASSWORD = self.prefs[account]['password']
        FOLDERLIST = self.prefs[account]['folder'].split(',')
        fname = os.path.join(
            os.path.dirname(__file__),
            'data',
            self.prefs[account]['blacklist'] if 'blacklist' in self.prefs[
                account] else self.prefs['DEFAULT']['blacklist'],
        )
        if os.path.isfile(fname):
            BLACKLISTFILE = fname
        BLACKLIST = self.get_black_or_white_list(BLACKLISTFILE)

        ssl_context = ssl.create_default_context()

        # check if certificate hostname matches target hostname
        ssl_context.check_hostname = True

        # check if the certificate is trusted by a certificate authority
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        if BLACKLIST:
            delete_count = 0
            with IMAPClient(HOST, ssl_context=ssl_context) as server:
                server.login(USERNAME, PASSWORD)
                for folder in FOLDERLIST:
                    try:
                        server.select_folder(folder.strip(), readonly=False)
                    except:
                        logger.error(
                            'Unknown Folder: %s',
                            folder,
                        )
                        return
                    logger.info(
                        'Processing folder "%s" for account "%s"',
                        folder,
                        USERNAME,
                    )
                    messages = server.search('ALL')
                    for uid, message_data in server.fetch(messages, 'RFC822').items():
                        email_message = email.message_from_bytes(
                            message_data[b'RFC822'])
                        received_ip = self.get_ip(email_message)
                        email_from = self.get_from(email_message)
                        if folder.strip().lower() == 'blacklist':
                            address = email_message.get('From')
                            if not address:
                                for defect in email_message.defects:
                                    dtype, address = defect.line.split(':', 1)
                                    if dtype.strip() == 'From':
                                        break
                            if address:
                                if '<' in address:
                                    address = address[address.index("<")+1:-1]
                                self.append_blacklist(BLACKLISTFILE, address)
                                if received_ip:
                                    self.append_blacklist(
                                        BLACKLISTFILE, received_ip)
                                server.delete_messages([uid])
                                delete_count += 1
                                logger.info(
                                    '%s "%s" "%s" has been deleted based on blacklist folder',
                                    uid,
                                    address,
                                    self.get_subject(email_message),
                                )
                        if email_from:
                            if next((s for s in BLACKLIST if re.search(s, received_ip)), None):
                                server.delete_messages([uid])
                                delete_count += 1
                                logger.info(
                                    '%s "%s" "%s" has been deleted on IP',
                                    uid,
                                    email_from,
                                    self.get_subject(email_message),
                                )
                                continue
                            if next((s for s in BLACKLIST if fuzz.ratio(s.lower(), email_from.lower()) >= 60), None):
                                self.append_blacklist(
                                    BLACKLISTFILE, received_ip)
                                server.delete_messages([uid])
                                delete_count += 1
                                logger.info(
                                    '%s "%s" "%s" has been deleted on From-ratio',
                                    uid,
                                    email_from,
                                    self.get_subject(email_message),
                                )
                                continue
                            if next((s for s in BLACKLIST if s.lower() in email_from.lower()), None):
                                self.append_blacklist(
                                    BLACKLISTFILE, received_ip)
                                server.delete_messages([uid])
                                delete_count += 1
                                logger.info(
                                    '%s "%s" "%s" has been deleted on in-From',
                                    uid,
                                    email_from,
                                    self.get_subject(email_message),
                                )
                                continue
                            if next((s for s in BLACKLIST if s.lower() in str(decode_header(email_message.get('Subject'))).lower()), None):
                                self.append_blacklist(
                                    BLACKLISTFILE, received_ip)
                                server.delete_messages([uid])
                                delete_count += 1
                                logger.info(
                                    '%s "%s" "%s" has been deleted on Subject',
                                    uid,
                                    email_from,
                                    self.get_subject(email_message),
                                )
                    server.close_folder()
                if delete_count == 0:
                    logger.info(
                        'No matching Emails found for %s!',
                        USERNAME,
                    )
                elif delete_count == 1:
                    logger.info(
                        "%s Email has been deleted for %s!",
                        delete_count,
                        USERNAME,
                    )
                else:
                    logger.info(
                        "%s Emails have been deleted for %s!",
                        delete_count,
                        USERNAME,
                    )

    def moveSpam(self, account):
        diff = set(['host', 'username', 'password', 'folder',
                    'inbox']).difference(set(self.prefs[account]))
        if diff:
            logger.error(
                'Missing parameter(s) %s in ini file for %s',
                diff,
                account,
            )
            return
        HOST = self.prefs[account]['host']
        USERNAME = self.prefs[account]['username']
        PASSWORD = self.prefs[account]['password']
        FOLDERLIST = self.prefs[account]['folder'].split(',')
        INBOX = self.prefs[account]['inbox']
        fname = os.path.join(
            os.path.dirname(__file__),
            'data',
            self.prefs[account]['whitelist'] if 'whitelist' in self.prefs[
                account] else self.prefs['DEFAULT']['whitelist'],
        )
        if os.path.isfile(fname):
            WHITELISTFILE = fname
        WHITELIST = self.get_black_or_white_list(WHITELISTFILE)

        ssl_context = ssl.create_default_context()

        # check if certificate hostname matches target hostname
        ssl_context.check_hostname = True

        # check if the certificate is trusted by a certificate authority
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        if WHITELIST:
            move_count = 0
            with IMAPClient(HOST, ssl_context=ssl_context) as server:
                server.login(USERNAME, PASSWORD)
                for folder in FOLDERLIST:
                    try:
                        server.select_folder(folder.strip(), readonly=False)
                    except:
                        logger.error(
                            'Unknown Folder: %s',
                            folder,
                        )
                        return
                    messages = server.search('ALL')
                    for uid, message_data in server.fetch(messages, 'RFC822').items():
                        email_message = email.message_from_bytes(
                            message_data[b'RFC822'])
                        if next((s for s in WHITELIST if email_message.get('From') and s in email_message.get('From')), None):
                            server.move([uid], INBOX)
                            move_count += 1
                            logger.info(
                                "%s %s %s has been moved",
                                uid,
                                email_message.get('From'),
                                email_message.get('Subject'),
                            )
                    server.close_folder()
                if move_count == 0:
                    logger.info(
                        'No matching Emails found for %s to be moved!',
                        USERNAME,
                    )
                elif move_count == 1:
                    logger.info(
                        "%s Email has been moved for %s!",
                        move_count,
                        USERNAME,
                    )
                else:
                    logger.info(
                        "%s Emails have been moved for %s!",
                        move_count,
                        USERNAME,
                    )


if __name__ == '__main__':
    print(f"Running script at {datetime.now()}")
    SpamCleaner()