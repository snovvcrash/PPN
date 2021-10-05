# VirtualBox




## DHCP

Configure DHCP in VBox:

```
Cmd > "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" dhcpserver add --netname intnet --ip 10.0.1.1 --netmask 255.255.255.0 --lowerip 10.0.1.101 --upperip 10.0.1.254 --enable
```




## Time Sync

Disable time synchronization with host OS (useful when syncing Kerberos time with ntpdate):

```
Cmd > VBoxManage setextradata "Kali Linux" "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled" 0
```




## Shared Folders (depreciated)

Mount:

```
$ mkdir ~/Desktop/Share
$ mount -t vboxsf /mnt/share-host ~/Desktop/Share
Or (if mounted from VBox settings)
$ ln -s /mnt/share-host ~/Desktop/Share

$ sudo usermod -aG vboxsf `whoami`
$ sudo reboot  # or re-login
```

Automount:

```
$ crontab -e
"@reboot    sleep 10; mount -t vboxsf /mnt/share-host ~/Desktop/Share"
```
