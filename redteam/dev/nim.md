# Nim

* [https://github.com/byt3bl33d3r/OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim)
* [https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim/](https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim/)
* [https://github.com/S3cur3Th1sSh1t/Creds/tree/master/nim](https://github.com/S3cur3Th1sSh1t/Creds/tree/master/nim)
* [https://github.com/ajpc500/NimExamples](https://github.com/ajpc500/NimExamples)
* [https://huskyhacks.dev/2021/07/17/nim-exploit-dev/](https://huskyhacks.dev/2021/07/17/nim-exploit-dev/)
* [https://casvancooten.com/posts/2021/08/building-a-c2-implant-in-nim-considerations-and-lessons-learned/](https://casvancooten.com/posts/2021/08/building-a-c2-implant-in-nim-considerations-and-lessons-learned/)




## Install

Windows:

* [https://nim-lang.org/install_windows.html](https://nim-lang.org/install_windows.html)
* [https://git-scm.com/download/win](https://git-scm.com/download/win)

Linux:

```
$ sudo apt install mingw-w64 -y
$ sudo apt install nim -y
Or
$ curl https://nim-lang.org/choosenim/init.sh -sSf | sh
```

Dependencies:

```
Nim > nimble install winim nimcrypto zippy
```




## Compilation

Basic:

```
Nim > nim c program.nim
```

To not popup the console window:

```
Nim > nim c --app:gui program.nim
```

For the best size:

```
Nim > nim c -d:danger -d:strip --opt:size --passC=-flto --passL=-flto program.nim
```

For Windows on Linux:

```
$ nim c --cpu:amd64 --os:windows --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc program.nim
```

Add the needed relocation section to the resulting executable (from Windows):

```
Nim > nim c --passL:-Wl,--dynamicbase,--export-all-symbols program.nim
```




## Tools & Packers

- [https://github.com/S3cur3Th1sSh1t/Nim-RunPE](https://github.com/S3cur3Th1sSh1t/Nim-RunPE)
- [https://github.com/S3cur3Th1sSh1t/NimGetSyscallStub](https://github.com/S3cur3Th1sSh1t/NimGetSyscallStub)
- [https://github.com/chvancooten/NimPackt-v1](https://github.com/chvancooten/NimPackt-v1)
- [https://github.com/icyguider/Nimcrypt2](https://github.com/icyguider/Nimcrypt2)
- [https://github.com/adamsvoboda/nim-loader](https://github.com/adamsvoboda/nim-loader)
