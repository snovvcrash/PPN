#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Usage: sudo ./gophish_postfix_smtp_injector.py 127.0.0.1 2525

"""
Based on:
- https://github.com/rc4/gophish-macro-attachment
- https://unix.stackexchange.com/questions/389323/forward-email-but-change-the-from-address
"""

import smtplib
import smtpd
import asyncore
import sys
import re
import email
from email import policy
from datetime import datetime
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('lhost', type=str, help='local host to start SMTP server')
parser.add_argument('lport', type=int, help='local port to start SMTP server')


class SMTPInjectorServer(smtpd.SMTPServer):

	RID_RE = re.compile(r'<!--\040RID:\040([a-z0-9]{6,})\040-->', re.IGNORECASE)
	MHT_RE = re.compile(r'\.mht$', re.IGNORECASE)
	MHT_PLACEHOLDER_RE = re.compile(b'{{\.RIDPLACEHOLDER}}')

	def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
		self._print_info('New email recieved')

		#print('Receiving message from:', peer)
		#print('Message addressed from:', mailfrom)
		#print('Message addressed to  :', rcpttos)
		#print('Message length        :', len(data))
		#print(data)

		msg = email.message_from_bytes(data, policy=policy.default)
		try:
			self._print_info(f'Started processing email to \033[1;39m{msg["To"]}\033[0m')
			for part in msg.walk():
				filename = part.get_filename() # get filename of part
				content_main = part.get_content_maintype()
				content_sub = part.get_content_subtype()

				if not filename and content_main != 'multipart': # body will not have a filename
					content = part.get_content()
					matches = self.RID_RE.search(content) # search for RID string in content
					if matches:
						rid_bytes = bytes(matches.group(1), 'utf-8')
						new_content = self.RID_RE.sub('', content)
						part.set_content(new_content, subtype=content_sub)
					else:
						continue

				elif filename and self.MHT_RE.search(filename):
					self._print_data(f'Attachemnt captured! RID=\033[1;39m{rid_bytes.decode("utf-8")}\033[0m')
					mht_filename = self.MHT_RE.sub('.doc', filename) # replace .mht with .doc
					mht_content = part.get_payload(decode=True)
					new_mht = self.MHT_PLACEHOLDER_RE.sub(rid_bytes, mht_content)
					part.set_content(new_mht, maintype=content_main, subtype=content_sub, cte='base64', filename=mht_filename)

		except Exception as e:
			self._print_error(sys.exc_info()[0])
			self._print_error(e)

		# Local SMTP instance
		conn = smtplib.SMTP('127.0.0.1', 25)
		#conn.set_debuglevel(1)
		#conn.starttls()
		conn.sendmail(msg['From'], msg['To'], msg.as_string())

		# Public relay (Yandex)
		#conn = smtplib.SMTP_SSL('smtp.yandex.ru', 465)
		#conn.set_debuglevel(1)
		#conn.ehlo()
		#conn.login('user@example.com', 'passw0rd')

		self._print_info('Message injected into Postfix')
		print()

		return

	def _print_info(self, msg):
		print(f'[\033[0;36m{datetime.now().strftime("%H:%M:%S")}\033[0m] [\033[0;32mINFO\033[0m] {msg}')

	def _print_data(self, msg):
		print(f'[\033[0;36m{datetime.now().strftime("%H:%M:%S")}\033[0m] [\033[0;34mDATA\033[0m] {msg}')

	def _print_error(self, msg):
		print(f'[\033[1;36m{datetime.now().strftime("%H:%M:%S")}\033[0m] [\033[1;31mERROR\033[0m] {msg}')


args = parser.parse_args()
print(f'Serving SMTP on {args.lhost} port {args.lport} ...')
server = SMTPInjectorServer((args.lhost, args.lport), None)
asyncore.loop()
