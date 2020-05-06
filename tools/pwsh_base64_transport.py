#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Usage: ./pwsh_base64_transport.py <INPUT_FILE> <OUTPUT_FILE> |xclip -i -sel c

from base64 import b64encode, b64decode
from hashlib import md5
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('input_file', help='path to file for transfer')
parser.add_argument('output_file', help='path to file for transfer')
parser.add_argument('-n', '--number', type=int, default=1000, help='chunk size for a single PS write command')


def get_pwsh_cmd(input_file, output_file, number):
	RM_CMD = f"""rm {output_file}.b64\n"""
	APPEND_CMD = f"""[System.IO.File]::AppendAllText("$pwd\\{output_file}.b64",'%s')\n"""
	#SLEEP_CMD = """Start-Sleep -s 2\n"""
	READ_CMD = f"""$data = [IO.File]::ReadAllText("$pwd\\{output_file}.b64")\n"""
	WRITE_CMD = f"""[IO.File]::WriteAllBytes("$pwd\\{output_file}", [Convert]::FromBase64String($data))\n"""
	LS_CMD = f"""ls {output_file}*\n"""
	HASH_CMD = f"""Get-FileHash -Alg MD5 {output_file}\nEcho "[+] Done";"""

	with open(input_file, 'rb') as f:
		contents = f.read()
		#print(f'[*] Original hashsum: {md5(contents).hexdigest()}\n')

	contents_b64 = b64encode(contents).decode()

	cmd = ''
	for i in range(0, len(contents_b64), number):
		cmd += APPEND_CMD % contents_b64[i:i+number]
		#cmd += SLEEP_CMD

	cmd = RM_CMD + cmd + READ_CMD + WRITE_CMD + LS_CMD + HASH_CMD

	return cmd


args = parser.parse_args()

cmd = get_pwsh_cmd(args.input_file, args.output_file, args.number)
print(cmd)
