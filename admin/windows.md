# Windows

## Processes

Kill process from cmd:

```text
Cmd > taskkill /f /im:calc.exe
```

## Secure Delete

### cipher

```text
Cmd > cipher /w:H
```

### sdelete

File:

```text
Cmd > sdelete -p 7 testfile.txt
```

Directory \(recursively\):

```text
Cmd > sdelete -p 7 -r "C:\temp"
```

Disk or partition:

```text
Cmd > sdelete -p 7 -c H:
```

## System Perfomance

```text
Cmd > perfmon /res
```

## Network

### Connections and Routes

```text
Cmd > netstat -b
Cmd > netstat -ano
Cmd > route print [-4]
```

### Clean Cache

```text
Cmd > netsh int ip reset
Cmd > netsh int tcp reset
Cmd > ipconfig /flushdns
Cmd > netsh winsock reset
Cmd > route -f
[Cmd> ipconfig -renew]
```

Hide/unhide computer name on LAN:

```text
Cmd > net config server
Cmd > net config server /hidden:yes
Cmd > net config server /hidden:no
(+ reboot)
```

## Symlinks

```text
Cmd > mklink Link <FILE>
Cmd > mklink /D Link <DIRECTORY>
```

## Wi-Fi Credentials

* [https://www.nirsoft.net/utils/wireless\_key.html\#DownloadLinks](https://www.nirsoft.net/utils/wireless_key.html#DownloadLinks)

```text
> netsh wlan show profiles
> netsh wlan show profiles "ESSID" key=clear
```

## Installed Software

```text
PS > Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize > InstalledSoftware.txt
```

## ADS

```text
PS > Get-Item 'file.txt' -Stream *
PS > Get-Content 'file.txt' -Stream Password
Or
PS > type 'file.txt:Password'
```

## .msc

```text
secpol.msc  -- Local Security Policy          -- «Локальная политика безопасности»
gpedit.msc  -- Local Group Policy Editor      -- «Редактор локальной групповой политики»
lusrmgr.msc -- Local Users and Groups (Local) -- «Локальные пользователи и группы (локально)»
certmgr.msc -- Certificates - Current User    -- «Сертификаты - текущий пользователь»
```

### Administrative Tools

```text
Cmd > mmc.exe %SystemRoot%\system32\dsa.msc     -- Active Directory Users and Computers
Cmd > mmc.exe %SystemRoot%\system32\dnsmgmt.msc -- DNS
Cmd > mmc.exe %SystemRoot%\system32\gpmc.msc    -- Group Policy Management
```

## KRShowKeyMgr

Run:

```text
rundll32.exe keymgr.dll, KRShowKeyMgr
```

## Permissions

Take own of a directory and remove it \(run cmd.exe as admin\):

```text
Cmd > takeown /F C:\$Windows.~BT\* /R /A 
Cmd > icacls C:\$Windows.~BT\*.* /T /grant administrators:F 
Cmd > rmdir /S /Q C:\$Windows.~BT\
```

## DISM

### TelnetClient

```text
Cmd > DISM /online /Enable-Feature /FeatureName:TelnetClient
```

## BitLocker

Check encryption status of all drives \(must be elevated\):

```text
Cmd > manage-bde -status
```

