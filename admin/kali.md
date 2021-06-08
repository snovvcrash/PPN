# Kali




## Configure

Mix settings list (both for hardware install and virtualization):

```
[VM] Disable screen lock (Power Manager -> Display, Security -> OFF)
[VM] Configure networks (+ remember to configure VBox DHCP first)
[All] Update && Upgrade (+ change /etc/apt/sources.list to HTTPS if getting "403 Forbidden" because of AV)
	$ sudo apt update && sudo upgrade -y
	$ sudo reboot
[VM] Install guest additions
	* Insert Guest Additions CD image and open terminal there
	$ cp /media/cdrom0/VBoxLinuxAdditions.run ~/Desktop && chmod 755 ~/Desktop/VBoxLinuxAdditions.run && sudo ~/Desktop/VBoxLinuxAdditions.run
	$ sudo reboot
	$ rm ~/Desktop/VBoxLinuxAdditions.run && sudo eject
[ALL] Manage users
	* Enable root or create new user
		SWITCH {
			CASE (root):
				$ sudo -i
				$ passwd root
				* Re-login as root
			CASE (non-root):
				$ sudo useradd -m -s /bin/bash -u 1337 snovvcrash
				$ sudo passwd snovvcrash
				$ sudo usermod -aG sudo snovvcrash
				* Re-login as snovvcrash
		}
	* Disable kali user [VM]
		SWITCH {
			CASE (lock):
				$ sudo usermod -L kali
				$ sudo usermod -s /sbin/nologin kali
				$ sudo chage -E0 kali
			CASE (delete):
				$ sudo userdel -r kali
		}
[ALL] Configure sudo
	* Increase sudo password timeout value or disable password prompt completely
	$ sudo visudo
		SWITCH {
			CASE (increase timeout):
				$ sudo sh -c 'echo "Defaults    env_reset,timestamp_timeout=45" > /etc/sudoers.d/snovvcrash'
			CASE (disable password):
				$ sudo sh -c 'echo "snovvcrash ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/snovvcrash'
		}
[ALL] Install cmake
	$ sudo apt install cmake -y
[ALL] Clone dotfiles
	$ git clone https://github.com/snovvcrash/dotfiles-linux ~/.dotfiles
[ALL] Run ~/.dotfiles/00-autoconfig scripts on the discretion
```




## VirtualBox



### Guest Additions

Known issues:

* [https://forums.virtualbox.org/viewtopic.php?f=3&t=96087](https://forums.virtualbox.org/viewtopic.php?f=3&t=96087)
* [https://www.ceos3c.com/hacking/kali-linux-2020-1-virtualbox-shared-clipboard-stopped-working-fixed/](https://www.ceos3c.com/hacking/kali-linux-2020-1-virtualbox-shared-clipboard-stopped-working-fixed/)



### Network

Configure multiple interfaces to work simultaneously:

```
$ cat /etc/network/interfaces
 # This file describes the network interfaces available on your system
 # and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

 # NAT
allow-hotplug eth0
iface eth0 inet dhcp

 # Internal
allow-hotplug eth1
iface eth1 inet dhcp

 # Host-only
allow-hotplug eth2
iface eth2 inet dhcp

 # The loopback network interface
auto lo
iface lo inet loopback
```

```
$ ifup eth0
$ ifup eth1
$ ifup eth2
```

* [https://unix.stackexchange.com/questions/37122/virtualbox-two-network-interfaces-nat-and-host-only-ones-in-a-debian-guest-on](https://unix.stackexchange.com/questions/37122/virtualbox-two-network-interfaces-nat-and-host-only-ones-in-a-debian-guest-on)
* [https://kali.training/topic/configuring-the-network/](https://kali.training/topic/configuring-the-network/)
* [https://www.blackmoreops.com/2013/11/25/how-to-fix-wired-network-interface-device-not-managed-error/](https://www.blackmoreops.com/2013/11/25/how-to-fix-wired-network-interface-device-not-managed-error/)
* [https://www.virtualbox.org/manual/ch06.html](https://www.virtualbox.org/manual/ch06.html)
* [https://forums.kali.org/showthread.php?29657-Only-one-of-multiple-wired-interfaces-(eth0-eth1-etc)-can-be-active-at-a-time](https://forums.kali.org/showthread.php?29657-Only-one-of-multiple-wired-interfaces-%28eth0-eth1-etc%29-can-be-active-at-a-time)



### Share Folder (depreciated)

Mount:

```
$ mkdir ~/Desktop/Share
$ mount -t vboxsf /mnt/share-host ~/Desktop/Share
Or (if mounted from VBox settings)
$ ln -s /mnt/share-host ~/Desktop/Share

$ sudo adduser $USER vboxsf
```

Automount:

```
$ crontab -e
"@reboot    sleep 10; mount -t vboxsf /mnt/share-host ~/Desktop/Share"
```
