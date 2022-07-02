# Malware Development

- [https://threadreaderapp.com/thread/1520676600681209858.html](https://threadreaderapp.com/thread/1520676600681209858.html)

[EIKAR](https://ru.wikipedia.org/wiki/EICAR-Test-File):

```
$ msfvenom -p windows/messagebox TITLE="EICAR" TEXT="X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" -f raw -o eikar.bin
```




## Blog Series



### @0xPat

- [Malware development part 1 - basics](https://0xpat.github.io/Malware_development_part_1/)
- [Malware development part 2 - anti dynamic analysis & sandboxes](https://0xpat.github.io/Malware_development_part_2/)
- [Malware development part 3 - anti-debugging](https://0xpat.github.io/Malware_development_part_3/)
- [Malware development part 4 - anti static analysis tricks](https://0xpat.github.io/Malware_development_part_4/)
- [Malware development part 5 - tips & tricks](https://0xpat.github.io/Malware_development_part_5/)
- [Malware development part 6 - advanced obfuscation with LLVM and template metaprogramming](https://0xpat.github.io/Malware_development_part_6/)
- [Malware development part 7 - Secure Desktop keylogger](https://0xpat.github.io/Malware_development_part_7/)
- [Malware development part 8 - COFF injection and in-memory execution](https://0xpat.github.io/Malware_development_part_8/)
- [Malware development part 9 - hosting CLR and managed code injection](https://0xpat.github.io/Malware_development_part_9/)



### @cocomelonc

- [Malware development: persistence - part 1. Registry run keys](https://cocomelonc.github.io/tutorial/2022/04/20/malware-pers-1.html)
- [Malware development: persistence - part 2. Screensaver hijack](https://cocomelonc.github.io/tutorial/2022/04/26/malware-pers-2.html)
- [Malware development: persistence - part 3. COM DLL hijack](https://cocomelonc.github.io/tutorial/2022/05/02/malware-pers-3.html)
- [Malware development: persistence - part 4. Windows services](https://cocomelonc.github.io/tutorial/2022/05/09/malware-pers-4.html)
- [Malware development: persistence - part 5. AppInit_DLLs](https://cocomelonc.github.io/tutorial/2022/05/16/malware-pers-5.html)
- [Malware development: persistence - part 6. Windows netsh helper DLL](https://cocomelonc.github.io/tutorial/2022/05/29/malware-pers-6.html)
- [Malware AV evasion: part 7. Disable Windows Defender](https://cocomelonc.github.io/tutorial/2022/06/05/malware-av-evasion-7.html)



### @preemptdev

- [Maelstrom: An Introduction](https://pre.empt.dev/posts/maelstrom-an-introduction/)
- [Maelstrom: The C2 Architecture](https://pre.empt.dev/posts/maelstrom-arch-episode-1/)
- [Maelstrom: Building the Team Server](https://pre.empt.dev/posts/maelstrom-arch-episode-2/)
- [Maelstrom: Writing a C2 Implant](https://pre.empt.dev/posts/maelstrom-the-implant/)



### @chvancooten

- [[PDF] Malware Development for Dummies (Cas van Cooten)](https://github.com/chvancooten/maldev-for-dummies/blob/main/Slides/Malware%20Development%20for%20Dummies%20-%20Hack%20in%20Paris%2030-06-2022%20%26%2001-07-2022.pdf)
- [https://github.com/chvancooten/maldev-for-dummies](https://github.com/chvancooten/maldev-for-dummies)




## PE Injection

- [https://gist.github.com/hasherezade/e6daa4124fab73543497b6d1295ece10](https://gist.github.com/hasherezade/e6daa4124fab73543497b6d1295ece10)
- [https://xakep.ru/2018/08/27/doppelganging-process/](https://xakep.ru/2018/08/27/doppelganging-process/)
- [https://xakep.ru/2022/04/21/herpaderping-and-ghosting/](https://xakep.ru/2022/04/21/herpaderping-and-ghosting/)
