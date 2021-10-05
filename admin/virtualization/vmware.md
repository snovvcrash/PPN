# VMWare




## Shared Folders
* [https://linuxhint.com/mount_vmware_shares_command_line_linux_vm/](https://linuxhint.com/mount_vmware_shares_command_line_linux_vm/)

Mount:

```
$ sudo mkdir /mnt/share-host
$ sudo mount -t fuse.vmhgfs-fuse .host:/share-host /mnt/share-host
```
