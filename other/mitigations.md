# Mitigations




## Network

Mitigating ARP spoofing:

{% file src="/.gitbook/assets/Ruijie Anti-ARP Spoofing Technical White Paper.pdf" %}




## AD

Common vulnerabilities & misconfigurations and recommendations:

* [https://www.infosecmatter.com/top-16-active-directory-vulnerabilities/#2-admincount-attribute-set-on-common-users](https://www.infosecmatter.com/top-16-active-directory-vulnerabilities/#2-admincount-attribute-set-on-common-users)
* [https://threadreaderapp.com/thread/1369309701050142720.html](https://threadreaderapp.com/thread/1369309701050142720.html)
* [https://s3cur3th1ssh1t.github.io/The-most-common-on-premise-vulnerabilities-and-misconfigurations/](https://s3cur3th1ssh1t.github.io/The-most-common-on-premise-vulnerabilities-and-misconfigurations/)
* [https://github.com/evilmog/ntlmv1-multi/blob/master/resources/checklist.txt](https://github.com/evilmog/ntlmv1-multi/blob/master/resources/checklist.txt)

SMB lateral-movement hardening:

* [https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f](https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f)
* [https://medium.com/palantir/restricting-smb-based-lateral-movement-in-a-windows-environment-ed033b888721](https://medium.com/palantir/restricting-smb-based-lateral-movement-in-a-windows-environment-ed033b888721)

{% file src="/.gitbook/assets/SMB Enumeration-Exploitation-Hardening (Anil BAS).pdf" %}

Antispam protection for Exchange:

{% file src="/.gitbook/assets/Antispam Forefront Protection 2010 (Exchange Server).pdf" %}

Detect stale, unused or fake computer accounts based on password age (replace `-90` with your domain's maximum computer account password age):

```
$date = [DateTime]::Today.AddDays(-90); Get-ADComputer -Filter '(Enabled -eq $true) -and (PasswordLastSet -le $date)' | select Name
```

Administrative Tier Model explained:

* [https://security-tzu.com/2020/03/23/mitigate-credential-theft-with-administrative-tier-model/](https://security-tzu.com/2020/03/23/mitigate-credential-theft-with-administrative-tier-model/)
