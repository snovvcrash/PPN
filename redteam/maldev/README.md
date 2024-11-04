# MalDev

- [https://threadreaderapp.com/thread/1520676600681209858.html](https://threadreaderapp.com/thread/1520676600681209858.html)
- [https://www.mdsec.co.uk/2022/07/part-1-how-i-met-your-beacon-overview/](https://www.mdsec.co.uk/2022/07/part-1-how-i-met-your-beacon-overview/)
- [https://www.mdsec.co.uk/2022/07/part-2-how-i-met-your-beacon-cobalt-strike/](https://www.mdsec.co.uk/2022/07/part-2-how-i-met-your-beacon-cobalt-strike/)
- [https://www.mdsec.co.uk/2022/08/part-3-how-i-met-your-beacon-brute-ratel/](https://www.mdsec.co.uk/2022/08/part-3-how-i-met-your-beacon-brute-ratel/)

{% embed url="https://gist.github.com/0prrr/c0954a638c55ab4b39e8b02ef312e806" caption="Malware Dev Reading List, 0prrr/All-Mal-Dev.md" %}

[EIKAR](https://ru.wikipedia.org/wiki/EICAR-Test-File) test file:

```
$ msfvenom -p windows/messagebox TITLE="EICAR" TEXT="X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" -f raw -o eikar.bin
```




## Blog Series / Books



### PE Structure (+ PEB/LDR)

- [https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/#the-common-ground)
- [https://viuleeenz.github.io/posts/2024/02/understanding-peb-and-ldr-structures-using-ida-and-lummastealer/](https://viuleeenz.github.io/posts/2024/02/understanding-peb-and-ldr-structures-using-ida-and-lummastealer/)
- [https://fareedfauzi.github.io/2024/07/13/PEB-Walk.html](https://fareedfauzi.github.io/2024/07/13/PEB-Walk.html)
- [https://print3m.github.io/blog/x64-winapi-shellcoding](https://print3m.github.io/blog/x64-winapi-shellcoding)
- [https://habr.com/ru/articles/808787/](https://habr.com/ru/articles/808787/)
- [https://nikhilh-20.github.io/blog/peb_phobos_ransomware/](https://nikhilh-20.github.io/blog/peb_phobos_ransomware/)
- [https://redops.at/en/blog/edr-analysis-leveraging-fake-dlls-guard-pages-and-veh-for-enhanced-detection](https://redops.at/en/blog/edr-analysis-leveraging-fake-dlls-guard-pages-and-veh-for-enhanced-detection)

![PE File Structure (by @Print3M)](https://print3m.github.io/imgs/x64-shellcoding-winapi/pe-structure.png)


#### A dive into the PE file format (0xRick)

- [A dive into the PE file format - Introduction](https://0xrick.github.io/win-internals/pe1/)
- [A dive into the PE file format - PE file structure - Part 1: Overview](https://0xrick.github.io/win-internals/pe2/)
- [A dive into the PE file format - PE file structure - Part 2: DOS Header, DOS Stub and Rich Header](https://0xrick.github.io/win-internals/pe3/)
- [A dive into the PE file format - PE file structure - Part 3: NT Headers](https://0xrick.github.io/win-internals/pe4/)
- [A dive into the PE file format - PE file structure - Part 4: Data Directories, Section Headers and Sections](https://0xrick.github.io/win-internals/pe5/)
- [A dive into the PE file format - PE file structure - Part 5: PE Imports (Import Directory Table, ILT, IAT)](https://0xrick.github.io/win-internals/pe6/)
- [A dive into the PE file format - PE file structure - Part 6: PE Base Relocations](https://0xrick.github.io/win-internals/pe7/)
- [A dive into the PE file format - LAB 1: Writing a PE Parser](https://0xrick.github.io/win-internals/pe8/)



### Malware development (0xPat)

- [Malware development part 1 - basics](https://0xpat.github.io/Malware_development_part_1/)
- [Malware development part 2 - anti dynamic analysis & sandboxes](https://0xpat.github.io/Malware_development_part_2/)
- [Malware development part 3 - anti-debugging](https://0xpat.github.io/Malware_development_part_3/)
- [Malware development part 4 - anti static analysis tricks](https://0xpat.github.io/Malware_development_part_4/)
- [Malware development part 5 - tips & tricks](https://0xpat.github.io/Malware_development_part_5/)
- [Malware development part 6 - advanced obfuscation with LLVM and template metaprogramming](https://0xpat.github.io/Malware_development_part_6/)
- [Malware development part 7 - Secure Desktop keylogger](https://0xpat.github.io/Malware_development_part_7/)
- [Malware development part 8 - COFF injection and in-memory execution](https://0xpat.github.io/Malware_development_part_8/)
- [Malware development part 9 - hosting CLR and managed code injection](https://0xpat.github.io/Malware_development_part_9/)



### Windows APT Warfare (Sheng-Hao Ma)

- [https://www.packtpub.com/product/windows-apt-warfare/9781804618110](https://www.packtpub.com/product/windows-apt-warfare/9781804618110)
- [https://github.com/PacktPublishing/Windows-APT-Warfare](https://github.com/PacktPublishing/Windows-APT-Warfare)
- [https://habr.com/ru/articles/766760/](https://habr.com/ru/articles/766760/)
- [https://xss.is/threads/87501/](https://xss.is/threads/87501/)



### Malware Development for Dummies (Cas van Cooten)

- [[PDF] Malware Development for Dummies (Cas van Cooten)](https://github.com/chvancooten/maldev-for-dummies/blob/main/Slides/Malware%20Development%20for%20Dummies%20-%20Hack%20in%20Paris%2030-06-2022%20%26%2001-07-2022.pdf)
- [https://github.com/chvancooten/maldev-for-dummies](https://github.com/chvancooten/maldev-for-dummies)



### Learning LLVM (sh4dy)

- [https://sh4dy.com/2024/06/29/learning_llvm_01/](https://sh4dy.com/2024/06/29/learning_llvm_01/)
- [https://sh4dy.com/2024/07/06/learning_llvm_02/](https://sh4dy.com/2024/07/06/learning_llvm_02/)
- [https://github.com/0xSh4dy/learning_llvm](https://github.com/0xSh4dy/learning_llvm)
