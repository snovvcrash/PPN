#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Usage: ./cred_stasher.py -U <USER_FILE> -P <PASS_FILE> [-d <DOMAIN_STRING>]

'''USER_FILE
username1
username2
username3
'''

'''PASS_FILE
passw0rd1
passw0rd2
passw0rd3
'''

from argparse import ArgumentParser


class Stasher:

	def __init__(self, userfile, passfile, domain=None):
		self.domain = domain

		with open(userfile, 'r', encoding='utf-8') as f:
			self.usernames = [u.strip().lower() for u in f.read().split('\n') if u]

		with open(passfile, 'r', encoding='utf-8') as f:
			self.passwords = [p.strip() for p in f.read().split('\n') if p]

	def _process_usernames(self):
		if self.domain:
			self.usernames = [f'{self.domain.upper()}\\{u}' for u in self.usernames]

	def _process_passwords(self):
		stashed = []
		for password in self.passwords:
			curr_pass = ''
			for i, c in enumerate(password):
				if i < 2 or i > len(password)-3:
					curr_pass += c
				else:
					curr_pass += '*'

			stashed.append(curr_pass)

		self.passwords = stashed

	def run(self):
		self._process_usernames()
		self._process_passwords()
		return sorted(f'{u}:{p}' for u, p in zip(self.usernames, self.passwords))


parser = ArgumentParser()
parser.add_argument('-U', '--userfile', required=True, help='file with usernames')
parser.add_argument('-P', '--passfile', required=True, help='file with passwords')
parser.add_argument('-d', '--domain', default=None, help='domain string')
args = parser.parse_args()

stasher = Stasher(args.userfile, args.passfile, args.domain)
result = stasher.run()

print('\n'.join(result))
