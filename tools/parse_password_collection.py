#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Usage: ./parse_password_collection.py <PATH_TO_DATA_DIRECTORY>
# LC_ALL=C sort -u --parallel=8 Collection.txt -o Collection-sorted.txt

import re
from pathlib import Path
from subprocess import check_output
from argparse import ArgumentParser

PRINTABLE = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '

DOMAINS = [
  # Default domains included
  "aol.com", "att.net", "comcast.net", "facebook.com", "gmail.com", "gmx.com", "googlemail.com",
  "google.com", "hotmail.com", "hotmail.co.uk", "mac.com", "me.com", "mail.com", "msn.com",
  "live.com", "sbcglobal.net", "verizon.net", "yahoo.com", "yahoo.co.uk",
  # Other global domains
  "email.com", "fastmail.fm", "games.com" # AOL, "gmx.net", "hush.com", "hushmail.com", "icloud.com",
  "iname.com", "inbox.com", "lavabit.com", "love.com" # AOL, "outlook.com", "pobox.com", "protonmail.ch", "protonmail.com", "tutanota.de", "tutanota.com", "tutamail.com", "tuta.io",
  "keemail.me", "rocketmail.com" # Yahoo, "safe-mail.net", "wow.com" # AOL, "ygm.com" # AOL,
  "ymail.com" # Yahoo, "zoho.com", "yandex.com",
  # United States ISP domains
  "bellsouth.net", "charter.net", "cox.net", "earthlink.net", "juno.com",
  # British ISP domains
  "btinternet.com", "virginmedia.com", "blueyonder.co.uk", "freeserve.co.uk", "live.co.uk",
  "ntlworld.com", "o2.co.uk", "orange.net", "sky.com", "talktalk.co.uk", "tiscali.co.uk",
  "virgin.net", "wanadoo.co.uk", "bt.com",
  # Domains used in Asia
  "sina.com", "sina.cn", "qq.com", "naver.com", "hanmail.net", "daum.net", "nate.com", "yahoo.co.jp", "yahoo.co.kr", "yahoo.co.id", "yahoo.co.in", "yahoo.com.sg", "yahoo.com.ph", "163.com", "yeah.net", "126.com", "21cn.com", "aliyun.com", "foxmail.com",
  # French ISP domains
  "hotmail.fr", "live.fr", "laposte.net", "yahoo.fr", "wanadoo.fr", "orange.fr", "gmx.fr", "sfr.fr", "neuf.fr", "free.fr",
  # German ISP domains
  "gmx.de", "hotmail.de", "live.de", "online.de", "t-online.de" # T-Mobile, "web.de", "yahoo.de",
  # Italian ISP domains
  "libero.it", "virgilio.it", "hotmail.it", "aol.it", "tiscali.it", "alice.it", "live.it", "yahoo.it", "email.it", "tin.it", "poste.it", "teletu.it",
  # Russian ISP domains
  "mail.ru", "rambler.ru", "yandex.ru", "ya.ru", "list.ru",
  # Belgian ISP domains
  "hotmail.be", "live.be", "skynet.be", "voo.be", "tvcablenet.be", "telenet.be",
  # Argentinian ISP domains
  "hotmail.com.ar", "live.com.ar", "yahoo.com.ar", "fibertel.com.ar", "speedy.com.ar", "arnet.com.ar",
  # Domains used in Mexico
  "yahoo.com.mx", "live.com.mx", "hotmail.es", "hotmail.com.mx", "prodigy.net.mx",
  # Domains used in Canada
  "yahoo.ca", "hotmail.ca", "bell.net", "shaw.ca", "sympatico.ca", "rogers.com",
  # Domains used in Brazil
  "yahoo.com.br", "hotmail.com.br", "outlook.com.br", "uol.com.br", "bol.com.br", "terra.com.br", "ig.com.br", "itelefonica.com.br", "r7.com", "zipmail.com.br", "globo.com", "globomail.com", "oi.com.br"
]

parser = ArgumentParser()
parser.add_argument('data_dir', type=str, help='path to directory with leaked data in text files')
args = parser.parse_args()

data_dir_path = Path(args.data_dir)
files = [x for x in list(data_dir_path.glob('**#')) if x.is_file()]
total = len(files)

output = open(f'{args.data_dir}-result.txt', 'w', encoding='utf-8')
unknown = open('unknown.txt', 'a+', encoding='utf-8')
ipv4_regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

for i, file in enumerate(files):
	size = check_output(['wc', '-l', file]).decode().strip()
	print(f'{i+1}/{total}: {size}')

	with open(file, 'r', encoding='utf-8') as fd:
		try:
			for line in fd:
				for delim in (':', ';', '|'):
					try:
						# line = '589633_589633_589633_vasu_os@opensols.com:JUNK:james'

						login, postfix = line.split('@', 1)
						# login = 589633_589633_589633_vasu_os, postfix = opensols.com:JUNK:james

						second_lvl_domain, postfix = postfix.split('.', 1)
						# second_lvl_domain = opensols, postfix = com:JUNK:james

						first_lvl_domain, password = postfix.rsplit(delim, 1)
						# first_lvl_domain = com:JUNK, password = james

						password = password.strip()
						if 4 < len(password) < 28 and \
						password[-1] not in ':;' and \
						all(c in PRINTABLE for c in password) and \
						all('@'+d not in password for d in DOMAINS) and \
						not ipv4_regex.search(password):
							output.write(password + '\n')
							break

					except ValueError:
						pass

				else:
					unknown.write(line)

		except UnicodeDecodeError:
			pass

output.close()
unknown.close()
