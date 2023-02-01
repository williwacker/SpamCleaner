import argparse
import configparser
import email
import logging
import os
import ssl
from pathlib import Path

from imapclient import IMAPClient

__version__ = '1.0.1'

# Enable logging
logfile = "/var/log/" + \
    os.path.splitext(os.path.basename(__file__))[
        0]+".log" if os.name == "posix" else ""
logging.basicConfig(format='%(asctime)s %(levelname)s [%(filename)s:%(lineno)s] %(message)s',
                    filename=logfile, level=logging.INFO)
logger = logging.getLogger(__name__)


class SpamCleaner():

    def __init__(self):
        args = self.__get_cli_arguments__()
        # args.configfile = ['gmx.ini']	# for debugging purposes only
        if args.configfile and Path(args.configfile[0]).is_file():
            self.prefs = self.__read_configuration__(args.configfile)
        else:
            print(
                'No config file provided or config file not found. Use "{} -c <config.ini>"'.format(os.path.basename(__file__)))
            return
        for account in self.prefs:
            self.cleanup(account)

    def get_blacklist(self, blacklist_file):
        if blacklist_file and Path(blacklist_file).is_file():
            return open(blacklist_file, 'r').read().splitlines()

    def append_blacklist(self, blacklist_file, address):
        blacklist = self.get_blacklist(blacklist_file)
        if blacklist:
            blacklist.append(address)
            blacklist = list(set(blacklist))
            bl = open(blacklist_file, 'w')
            bl.write('\n'.join(blacklist))
            bl.close()

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
        for sectionname, section in cfg.items():
            preferences[sectionname] = {}
            for name, value in cfg.items(sectionname):
                preferences[sectionname][name] = value
        return preferences

    def cleanup(self, account):
        if set(['host', 'username', 'password', 'folder']).difference(set(self.prefs[account])):
            return
        HOST = self.prefs[account]['host']
        USERNAME = self.prefs[account]['username']
        PASSWORD = self.prefs[account]['password']
        FOLDERLIST = self.prefs[account]['folder'].split(',')
        BLACKLISTFILE = self.prefs[account]['blacklist'] if 'blacklist' in self.prefs[
            account] else self.prefs['DEFAULT']['blacklist']
        BLACKLIST = self.get_blacklist(BLACKLISTFILE)
        if not BLACKLIST:
            return

        ssl_context = ssl.create_default_context()

        # check if certificate hostname matches target hostname
        ssl_context.check_hostname = True

        # check if the certificate is trusted by a certificate authority
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        delete_count = 0
        with IMAPClient(HOST, ssl_context=ssl_context) as server:
            server.login(USERNAME, PASSWORD)
            for folder in FOLDERLIST:
                try:
                    server.select_folder(folder.strip(), readonly=False)
                except:
                    print('Unknown Folder')
                    return
                messages = server.search('ALL')
                for uid, message_data in server.fetch(messages, 'RFC822').items():
                    email_message = email.message_from_bytes(
                        message_data[b'RFC822'])
                    if folder.strip().lower() == 'blacklist':
                        address = email_message.get('From')
                        self.append_blacklist(
                            BLACKLISTFILE, address[address.index("<")+1:-1])
                        server.delete_messages([uid])
                        delete_count += 1
                        logger.info("{} {} {} has been deleted".format(
                            uid, email_message.get('From'), email_message.get('Subject')))
                    if next((s for s in BLACKLIST if email_message.get('From') and s in email_message.get('From')), None):
                        server.delete_messages([uid])
                        delete_count += 1
                        logger.info("{} {} {} has been deleted".format(
                            uid, email_message.get('From'), email_message.get('Subject')))
                server.close_folder()
            if delete_count == 0:
                logger.info(
                    'No matching Emails found for {}!'.format(USERNAME))
            elif delete_count == 1:
                logger.info("{} Email has been deleted for {}!".format(
                    delete_count, USERNAME))
            else:
                logger.info("{} Emails have been deleted for {}!".format(
                    delete_count, USERNAME))


SpamCleaner()
