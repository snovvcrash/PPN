# VMWare

- [https://www.kali.org/docs/virtualization/install-vmware-guest-tools/](https://www.kali.org/docs/virtualization/install-vmware-guest-tools/)


## Shared Folders

* [https://linuxhint.com/mount_vmware_shares_command_line_linux_vm/](https://linuxhint.com/mount_vmware_shares_command_line_linux_vm/)

List shares:

```
$ vmware-hgfsclient
```

Mount:

```
$ sudo mkdir /mnt/share-host

$ sudo mount -t fuse.vmhgfs-fuse .host:/share-host /mnt/share-host
Or
$ sudo vmhgfs-fuse .host:/share-host /mnt/share-host -o allow_other,uid=$UID,gid=$GID

$ echo '.host:/share-host /mnt/share-host fuse.vmhgfs-fuse defaults,allow_other,uid=1001,gid=1001 0 0' >> /etc/fstab
```
