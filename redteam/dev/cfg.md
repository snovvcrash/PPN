---
description: Control Flow Guard
---

# CFG

- [[PDF] Bypass Control Flow Guard Comprehensively (Zhang Yunhai)](https://www.blackhat.com/docs/us-15/materials/us-15-Zhang-Bypass-Control-Flow-Guard-Comprehensively-wp.pdf)
- [https://habr.com/ru/companies/dsec/articles/305960/](https://habr.com/ru/companies/dsec/articles/305960/)




## CFG Bypasses for Module Stomping



### Patch

- [https://www.secforce.com/blog/dll-hollowing-a-deep-dive-into-a-stealthier-memory-allocation-variant/](https://www.secforce.com/blog/dll-hollowing-a-deep-dive-into-a-stealthier-memory-allocation-variant/)



### Mark as Valid (SetProcessValidCallTargets)

- [https://www.fortinet.com/blog/threat-research/documenting-the-undocumented-adding-cfg-exceptions](https://www.fortinet.com/blog/threat-research/documenting-the-undocumented-adding-cfg-exceptions)
- [https://github.com/Crypt0s/Ekko_CFG_Bypass/blob/main/Ekko_CFG_Bypass/CFG.c#L8-L39](https://github.com/Crypt0s/Ekko_CFG_Bypass/blob/main/Ekko_CFG_Bypass/CFG.c#L8-L39)
- [https://github.com/Crypt0s/Ekko_CFG_Bypass/blob/main/Ekko_CFG_Bypass/CFG.c#L41-L86](https://github.com/Crypt0s/Ekko_CFG_Bypass/blob/main/Ekko_CFG_Bypass/CFG.c#L41-L86)
- [https://github.com/BreakingMalwareResearch/CFGExceptions/blob/master/CFGExceptions/main.cpp](https://github.com/BreakingMalwareResearch/CFGExceptions/blob/master/CFGExceptions/main.cpp)
- [https://blog.f-secure.com/hiding-malicious-code-with-module-stomping/](https://blog.f-secure.com/hiding-malicious-code-with-module-stomping/)
- [https://github.com/WithSecureLabs/ModuleStomping/blob/master/injectionUtils/moduleManipulation.cpp#L231-L239](https://github.com/WithSecureLabs/ModuleStomping/blob/master/injectionUtils/moduleManipulation.cpp#L231-L239)

Mark everything in the target module as valid:

```cpp
void markCFGValid(unsigned long long ptrToMarkValid)
{
    CFG_CALL_TARGET_INFO info;
    info.Flags = CFG_CALL_TARGET_VALID;
    info.Offset = ptrToMarkValid;

    if (!SetProcessValidCallTargets_(targetProcess, targetModuleBase, sizeOfImage, 1, &info))
        throw std::exception("SetProcessValidCallTargets failed");
}

if (srcSect.Characteristics & IMAGE_SCN_MEM_EXECUTE)
    for (unsigned int n = 0; n < srcSect.VirtualSize; n += 16)
        targetModule.markCFGValid(n);
```
