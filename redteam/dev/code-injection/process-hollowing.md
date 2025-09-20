# Process Hollowing




## Hollow with Shellcode

* [https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Shellcode%20Process%20Hollowing/Program.cs](https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Shellcode%20Process%20Hollowing/Program.cs)
* [https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/DinvokeProcessHollow.cs](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/DinvokeProcessHollow.cs)

1\. Create the target process (e. g., `svchost.exe`) in a suspended state.

![](/.gitbook/assets/004.png)

2\. Query created process to extract its base address pointer from PEB (**P**rocess **E**nvironment **B**lock).

![](/.gitbook/assets/005.png)

3\. Read 8 bytes of memory (for 64-bit architecture) pointed by the image base address *pointer* in order to get the actual value of the image base address.

![](/.gitbook/assets/006.png)

4\. Read 0x200 bytes of the loaded EXE image and parse PE structure to get the EntryPoint address.

![](/.gitbook/assets/007.png)

5\. Write the shellcode to the EntryPoint address and resume thread execution.

![](/.gitbook/assets/008.png)




## Hollow with EXE

* [https://github.com/m0n0ph1/Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
* [https://gist.github.com/gnh1201/6a3836468c898f7ad3a3656e6f24dce3](https://gist.github.com/gnh1201/6a3836468c898f7ad3a3656e6f24dce3)
* [https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)
