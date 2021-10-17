# Mitigations




## Network

Mitigating ARP spoofing:

* [[PDF] Ruijie Anti-ARP Spoofing Technical White Paper](https://drive.google.com/file/d/12V2xbiCZn-YupiGc4mxYWjOmCPFNUss9/view?usp=sharing)




## AD

Common vulnerabilities & misconfigurations and recommendations:

* [https://www.infosecmatter.com/top-16-active-directory-vulnerabilities/#2-admincount-attribute-set-on-common-users](https://www.infosecmatter.com/top-16-active-directory-vulnerabilities/#2-admincount-attribute-set-on-common-users)
* [https://threadreaderapp.com/thread/1369309701050142720.html](https://threadreaderapp.com/thread/1369309701050142720.html)
* [https://s3cur3th1ssh1t.github.io/The-most-common-on-premise-vulnerabilities-and-misconfigurations/](https://s3cur3th1ssh1t.github.io/The-most-common-on-premise-vulnerabilities-and-misconfigurations/)
* [https://github.com/evilmog/ntlmv1-multi/blob/master/resources/checklist.txt](https://github.com/evilmog/ntlmv1-multi/blob/master/resources/checklist.txt)

SMB lateral-movement hardening:

* [https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f](https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f)
* [https://medium.com/palantir/restricting-smb-based-lateral-movement-in-a-windows-environment-ed033b888721](https://medium.com/palantir/restricting-smb-based-lateral-movement-in-a-windows-environment-ed033b888721)
* [[PDF] SMB Enumeration & Exploitation & Hardening (Anil BAS)](https://drive.google.com/file/d/13msLIywr_Slc00Rv3jue0lkRf7_1O1gM/view?usp=sharing)

Antispam protection for Exchange:

* [[PDF] Antispam Forefront Protection 2010 (Exchange Server)](https://drive.google.com/file/d/1B-HUcZMZkFjqNs3ckuiiTpYSKdI0EsiR/view?usp=sharing)

Detect stale, unused or fake computer accounts based on password age (replace `-90` with your domain's maximum computer account password age):

```
$date = [DateTime]::Today.AddDays(-90); Get-ADComputer -Filter '(Enabled -eq $true) -and (PasswordLastSet -le $date)' | select Name
```

Administrative Tier Model explained:

* [https://security-tzu.com/2020/03/23/mitigate-credential-theft-with-administrative-tier-model/](https://security-tzu.com/2020/03/23/mitigate-credential-theft-with-administrative-tier-model/)
