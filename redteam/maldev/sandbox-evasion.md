# Sandbox Evasion

- [https://github.com/Arvanaghi/CheckPlease](https://github.com/Arvanaghi/CheckPlease)
- [https://github.com/LordNoteworthy/al-khaser](https://github.com/LordNoteworthy/al-khaser)
- [https://0xpat.github.io/Malware_development_part_2/](https://0xpat.github.io/Malware_development_part_2/)




## Code Snippets

Check if a machine a domain-joined (sandbox evasion):

{% code title="is_domain_joined.py" %}
```cpp
// cl.exe is_domain_joined.cpp netapi32.lib
#include <Windows.h>
#include <LM.h>
#include <iostream>

BOOL IsDomainJoined() {
	auto joined = false;
	LPWSTR lpNameBuffer = nullptr;
	NETSETUP_JOIN_STATUS joinStatus = NETSETUP_JOIN_STATUS::NetSetupUnknownStatus;

	NET_API_STATUS status = NetGetJoinInformation(nullptr, &lpNameBuffer, &joinStatus);
	if (status == NERR_Success)
		joined = joinStatus == NETSETUP_JOIN_STATUS::NetSetupDomainName;

	if (lpNameBuffer)
		NetApiBufferFree(lpNameBuffer);

	return joined;
}

int main()
{
    std::cout << (!IsDomainJoined() ? "No dynamic analysis 4 U" : "Hack the Planet!") << std::endl;
}
```
{% endcode %}
