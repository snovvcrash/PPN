# MalDev

- [https://threadreaderapp.com/thread/1520676600681209858.html](https://threadreaderapp.com/thread/1520676600681209858.html)
- [https://www.mdsec.co.uk/2022/07/part-1-how-i-met-your-beacon-overview/](https://www.mdsec.co.uk/2022/07/part-1-how-i-met-your-beacon-overview/)
- [https://www.mdsec.co.uk/2022/07/part-2-how-i-met-your-beacon-cobalt-strike/](https://www.mdsec.co.uk/2022/07/part-2-how-i-met-your-beacon-cobalt-strike/)
- [https://www.mdsec.co.uk/2022/08/part-3-how-i-met-your-beacon-brute-ratel/](https://www.mdsec.co.uk/2022/08/part-3-how-i-met-your-beacon-brute-ratel/)

[EIKAR](https://ru.wikipedia.org/wiki/EICAR-Test-File) Test File:

```
$ msfvenom -p windows/messagebox TITLE="EICAR" TEXT="X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" -f raw -o eikar.bin
```




## Code Snippets



### C++

XOR encryption:

```cpp
void XOR(char* data, size_t data_len) {
    const char key[] = "abcdefghjiklmnopqrstuvwxyz";

    int j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == sizeof(key) - 1) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}
```

AES encryption:

```cpp
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
```

Invoke the shellcode [from an embed resource](https://www.ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources):

```cpp
HRSRC scResource = FindResource(NULL, MAKEINTRESOURCE(IDR_RESOURCE_BIN1), "RESOURCE_BIN");
DWORD shellcodeSize = SizeofResource(NULL, scResource);
HGLOBAL scResourceData = LoadResource(NULL, scResource);

unsigned char* shellcode;
shellcode = (unsigned char*)malloc(shellcodeSize);

memcpy(shellcode, scResourceData, shellcodeSize);
```



### Python

Run OS command:

{% code title="runCmd.py" %}
```python
import subprocess, shlex

def run_command(command):
	process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False)
	while True:
		output = process.stdout.readline().decode()
		if output == '' and process.poll() is not None:
			break
		if output:
			print(output.strip())
	res = process.poll()
	return res
```
{% endcode %}




## Blog Series / Books

- [https://cocomelonc.github.io/](https://cocomelonc.github.io/)



### PE Structure

- [https://viuleeenz.github.io/posts/2024/02/understanding-peb-and-ldr-structures-using-ida-and-lummastealer/](https://viuleeenz.github.io/posts/2024/02/understanding-peb-and-ldr-structures-using-ida-and-lummastealer/)
- [https://fareedfauzi.github.io/2024/07/13/PEB-Walk.html](https://fareedfauzi.github.io/2024/07/13/PEB-Walk.html)
- [https://print3m.github.io/blog/x64-winapi-shellcoding](https://print3m.github.io/blog/x64-winapi-shellcoding)

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
