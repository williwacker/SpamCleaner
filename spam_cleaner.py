import argparse
import configparser
import email
import logging
import os
import ssl
from pathlib import Path

from imapclient import IMAPClient

__version__ = '1.0.0'

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
		#args.configfile = 'gmx2.ini'	# for debugging purposes only
		if args.configfile and Path(args.configfile).is_file():
			self.prefs = self.__read_configuration__(args.configfile)
		else:
			print(
				'No config file provided or config file not found. Use "{} -c <config.ini>"'.format(os.path.basename(__file__)))
			return
		self.blacklist = self.get_blacklist()
		self.cleanup()

	def get_blacklist(self):
		if self.prefs['DEFAULT']['blacklist'] and Path(self.prefs['DEFAULT']['blacklist']).is_file():
			return open(self.prefs['DEFAULT']['blacklist'], 'r').read().splitlines()

	def append_blacklist(self, address):
		if self.prefs['DEFAULT']['blacklist'] and Path(self.prefs['DEFAULT']['blacklist']).is_file():
			bl = open(self.prefs['DEFAULT']['blacklist'], 'a')
			bl.write(address)
			bl.write("\n")
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

	def cleanup(self):
		HOST = self.prefs['DEFAULT']['host']
		USERNAME = self.prefs['DEFAULT']['username']
		PASSWORD = self.prefs['DEFAULT']['password']
		FOLDERLIST = self.prefs['DEFAULT']['folder'].split(',')

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
						self.append_blacklist(address[address.index("<")+1:-1])
						server.delete_messages([uid])
						delete_count += 1
					if next((s for s in self.blacklist if s in email_message.get('From')), None):
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
