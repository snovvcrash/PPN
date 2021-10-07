# Kali

* [https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/](https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/)




## Branches

Switch to the most stable branch:

```
$ echo "deb http://http.kali.org/kali kali-last-snapshot main non-free contrib" | sudo tee /etc/apt/sources.list
```




## Setup Checklist

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




## Tricks

When dealing with an engagement where there's no internet access available on the attacker's box, one can use [paperify](https://github.com/alisinabh/paperify) to send data to her teammates (hashes to brute force, for example).

Zip the hashes with best compression, base64 the archive and create a QR code:

```
$ 7z a -t7z -m0=lzma -mx=9 -mfb=64 -md=32m -ms=on archive.7z tgsrep.txt
$ base64 -w0 archive.7z > 7z
$ ./paperify.sh 7z
```

Translate the QR code with your favorite mobile app and send the contents via a secure channel (e. g., a messenger). Now your teammates can reverse the process to get the initial zip file:

```
PS > b64decode.ps1 .\b64.txt out.7z
```

{% code title="b64decode.ps1" %}
```powershell
$IN = $args[0]
$OUT = $args[1]
$data = [IO.File]::ReadAllText("$pwd\$IN")
[IO.File]::WriteAllBytes("$pwd\$OUT", [Convert]::FromBase64String($data))
```
{% endcode %}
