# Malware Development

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
	process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE)
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




## Blog Series



### @0xPat

- [Malware development part 1 - basics](https://0xpat.github.io/Malware_development_part_1/)
- [Malware development part 2 - anti dynamic analysis & sandboxes](https://0xpat.github.io/Malware_development_part_2/)
- [Malware development part 3 - anti-debugging](https://0xpat.github.io/Malware_development_part_3/)
- [Malware development part 4 - anti static analysis tricks](https://0xpat.github.io/Malware_development_part_4/)
- [Malware development part 5 - tips & tricks](https://0xpat.github.io/Malware_development_part_5/)
- [Malware development part 6 - advanced obfuscation with LLVM and template metaprogramming](https://0xpat.github.io/Malware_development_part_6/)
- [Malware development part 7 - Secure Desktop keylogger](https://0xpat.github.io/Malware_development_part_7/)
- [Malware development part 8 - COFF injection and in-memory execution](https://0xpat.github.io/Malware_development_part_8/)
- [Malware development part 9 - hosting CLR and managed code injection](https://0xpat.github.io/Malware_development_part_9/)



### @cocomelonc

- [Malware development: persistence - part 1. Registry run keys](https://cocomelonc.github.io/tutorial/2022/04/20/malware-pers-1.html)
- [Malware development: persistence - part 2. Screensaver hijack](https://cocomelonc.github.io/tutorial/2022/04/26/malware-pers-2.html)
- [Malware development: persistence - part 3. COM DLL hijack](https://cocomelonc.github.io/tutorial/2022/05/02/malware-pers-3.html)
- [Malware development: persistence - part 4. Windows services](https://cocomelonc.github.io/tutorial/2022/05/09/malware-pers-4.html)
- [Malware development: persistence - part 5. AppInit_DLLs](https://cocomelonc.github.io/tutorial/2022/05/16/malware-pers-5.html)
- [Malware development: persistence - part 6. Windows netsh helper DLL](https://cocomelonc.github.io/tutorial/2022/05/29/malware-pers-6.html)
- [Malware AV evasion: part 7. Disable Windows Defender](https://cocomelonc.github.io/tutorial/2022/06/05/malware-av-evasion-7.html)



### @preemptdev

- [Mez0: Maelstrom](https://mez0.cc/posts/maelstrom/)



### @chvancooten

- [[PDF] Malware Development for Dummies (Cas van Cooten)](https://github.com/chvancooten/maldev-for-dummies/blob/main/Slides/Malware%20Development%20for%20Dummies%20-%20Hack%20in%20Paris%2030-06-2022%20%26%2001-07-2022.pdf)
- [https://github.com/chvancooten/maldev-for-dummies](https://github.com/chvancooten/maldev-for-dummies)
