# WinDbg

- [https://blog.talosintelligence.com/unravelling-net-with-help-of-windbg/](https://blog.talosintelligence.com/unravelling-net-with-help-of-windbg/)




## Install

- [https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- [https://github.com/TimMisiak/windup](https://github.com/TimMisiak/windup)

Get the latest version (stolen from [here](https://stackoverflow.com/a/77062861/6253579)):

```bash
wget --quiet --continue  --no-check-certificate -O windbg.appinstaller https://aka.ms/windbg/download
grep -ioP "htt.*bundle" windbg.appinstaller > msix.txt
wget --quiet --continue  --no-check-certificate -i msix.txt
7z.exe x windbg.msixbundle 
7z.exe x *x64.msix -owindbgnew
cd windbgnew
start dbgx.shell.exe
```



### Symbols

- [https://github.com/p0dalirius/pdbdownload](https://github.com/p0dalirius/pdbdownload)




## Cheatsheet

Load debugging symbols:

```
> srv*c:\symbols*https://msdl.microsoft.com/download/symbols
> .reload /f
```

Unassemble from memory:

```
> u kernel32!GetCurrentThread
```

Read bytes from memory:

```
> db esp [L1]
> db 41414141
> db kernel32!WriteFile

> dw esp
> dd esp
> dq esp

> dW/dc KERNELBASE+0x40
```

Read data at a specified address:

```
> dd esp L1
41414141
> dd 41414141
// The same as pointer to data
> dd poi(esp)
```

Dump structures:

```
> dt ntdll!_TEB
> dt -r ntdll!_TEB @$teb ThreadLocalStoragePointer
> dt -r ntdll!_TEB @$teb

> ?? sizeof(ntdll!_TEB)
```

Edit bytes:

```
> dd esp L1
> ed esp 41414141
> dd esp L1

> da esp
> ea esp "AAAA"
> da esp
```

Search memory space:

```
> ed esp 41414141
> s -d 0 L?80000000 41414141

> s -a 0 L?80000000 "This program cannot be run in DOS mode"
```

Work with registers:

```
> r
> r eax
> r eax=41414141
```

Work with software breakpoints:

```
> bp kernel32!WriteFile
> bl
> bd 0
> be 0
> bc 0
> bc *

> lm m ole32
> bu ole32!WriteStringStream
> bl
```

Breakpoints and actions:

```
BOOL WriteFile(
  HANDLE       hFile,
  LPCVOID      lpBuffer,
  DWORD        nNumberOfBytesToWrite,  // Write to file "hello" -> "db esp+0x0c L1" is 04 (length of "hello", also in esi register)
  LPDWORD      lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);

> bp kernel32!WriteFile ".printf \"The number of bytes written is: %p\", poi(esp + 0x0C);.echo;g"
> bp kernel32!WriteFile ".if (poi(esp + 0x0C) != 4) {gc} .else {.printf \"The number of bytes written is 4\";.echo;}"
> bp kernel32!WriteFile ".if (@esi != 4) {gc} .else {.printf \"The number of bytes written is 4\";.echo;}"
```

Work with hardware breakpoints:

```
// Before: write "w00tw00t" to a file, save the file, close Notepad, re-open the file
> s -a 0x0 L?80000000 w00tw00t
> s -u 0x0 L?80000000 w00tw00t
> ba w 2 00b8b238
> du
00b8b238  "a00tw00t"
```

![[Pasted image 20230924234241.png]]

Step through code:

```
> p   // step over
> t   // step into
> pt  // step to next return
> ph  // execute code until a branching instruction is reached
```

List modules and symbols:

```
> .reload /f
> lm
> lm m kernel*
> x kernelbase!CreateProc*
```

Evaluation and output formats:

```
> ? ((41414141 - 414141) * 0n10) >> 8
> ? 41414141
> ? 0n41414141
> ? 0y10101010
> .formats 41414141
```

Pseudo registers:

```
> r @$t0 = (41414141 - 414141) * 0n10
> ? @$t0 >> 8
```
