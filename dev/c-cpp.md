# C / C++




## C Library Path

```
$ echo '#include <sys/types.h>'' | gcc -E -x c - | grep '/types.h'
```




## Vangrind

```
$ valgrind --leak-check=full --track-origins=yes --leak-resolution=med ./a.out
```




## Return Address on Stack in Windows

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
