# Unix




## Encodings

From CP1252 to UTF-8:

```
$ iconv -f CP1252 -t UTF8 inputfile.txt -o outputfile.txt
Or
$ enconv -x UTF8 somefile.txt
```

Check:

```
$ enconv -d somefile.txt
Or
$ file -i somefile.txt
```

Remove ANSI escape codes:

```
$ awk '{ gsub("\\x1B\\[[0-?]*[ -/]*[@-~]", ""); print }' somefile.txt
```



### Windows/Unix Text

```
input.txt: ASCII text
VS
input.txt: ASCII text, with CRLF line terminators
```

From Win to Unix:

```
$ awk '{ sub("\r$", ""); print }' input.txt > output.txt
Or
$ dos2unix input.txt
```

From Unix to Win:

```
$ awk 'sub("$", "\r")' input.txt > output.txt
Or
$ unix2dos input.txt
```




## Network



### Connections

```
$ netstat -anlp | grep LIST
$ ss -nlpt | grep LIST
```



### Public IP

```
$ wget -q -O - https://ipinfo.io/ip
$ curl ifconfig.me; echo
$ dig +time=1 +tcp +tries=1 +short txt ch whoami.cloudflare @1.0.0.1 | tr -d '\"'
```



### Internel Speed

```
$ curl https://speedtest.selectel.ru/100MB -o/dev/null
$ curl --connect-to ::speedtest.selectel.ru https://manifest.googlevideo.com/100MB -k -o/dev/null
$ speedtest-cli
```




## Virtual Terminal

```
Start:
CTRL + ALT + F1-6

Stop:
ALT + F8
```




## Process Kill

```
$ ps aux | grep firefox
Or
$ pidof firefox

$ kill -15 <PID>
Or
$ kill -SIGTERM <PID>
Or
$ kill <PID>

If -15 signal didn't help, use stronger -9 signal:
$ kill -9 <PID>
Or
$ kill -SIGKILL <PID>
```




## OpenSSL



### Encrypt/Decrypt

```
$ openssl enc -e -aes-128-ecb -in file.txt -out file.txt.ecb -K 10101010
$ openssl enc -d -aes-128-ecb -in file.txt.ecb -out file.txt.ecb_dec -K 10101010

$ echo 'secret_data1 + secret_data2 + secret_data3' | openssl enc -e -aes-256-cbc -a -salt -md sha256 -iv 10101010 -pass pass:qwerty
$ echo 'U2FsdGVkX1+d1qH1M3nhYFKscrg5QYt+AlTSBPHgdB4JEP8YSy1FX+xYdrfJ5cZgfoGrW+2On7lMxRIhKCUmWQ==' | openssl enc -d -aes-256-cbc -a -salt -md sha256 -iv 10101010 -pass pass:qwerty
```



### Generate Keys

```
$ ssh-keygen -t rsa -b 4096 -N 's3cr3t_p4ssw0rd' -C 'user@email.com' -f rsa_key
$ mv rsa_key rsa_key.old
$ openssl pkcs8 -topk8 -v2 des3 \
  -in rsa_key.old -passin 'pass:s3cr3t_p4ssw0rd' \
  -out rsa_key -passout 'pass:s3cr3t_p4ssw0rd'
$ chmod 600 rsa_key

$ openssl rsa -text -in rsa_key -passin 'pass:s3cr3t_p4ssw0rd'
$ openssl asn1parse -in rsa_key

$ ssh-keygen -o -a 100 -t ed25519 -f ~/.ssh/id_ed25519
```




## GPG

* [https://www.linode.com/docs/security/encryption/gpg-keys-to-send-encrypted-messages/](https://www.linode.com/docs/security/encryption/gpg-keys-to-send-encrypted-messages/)
* [https://habr.com/ru/post/358182/](https://habr.com/ru/post/358182/)
* [https://hackware.ru/?p=8215](https://hackware.ru/?p=8215)

List keychain:

```
$ gpg --list-keys
```

Gen key:

```
$ gpg --full-generate-key [--expert]
```

Gen revoke cert:

```
$ gpg --output revoke.asc --gen-revoke user@example.com
revoke.asc
```

Export user's public key:

```
$ gpg --armor --output user.pub --export user@example.com
user.pub
```

Import recipient's public key:

```
$ gpg --import recipient.pub
```

Sign and encrypt:

```
$ gpg -o/--output encrypted.txt.gpg -e/--encrypt -s/--sign -u/--local-user user1@example.com -r/--recipient user2@example.com plaintext.txt
encrypted.txt.gpg
```

List recipients:

```
$ gpg --list-only -v -d/--decrypt encrypted.txt.gpg
```

Verify signature:

```
$ gpg --verify signed.txt.gpg
$ gpg --verify signed.txt.sig signed.txt
```

Decrypt and verify:

```
$ gpg -o/--output decrypted.txt -d/--decrypt --try-secret-key user1@example.com encrypted.txt.gpg
$ gpg -o/--output decrypted.txt -d/--decrypt -u/--local-user user1@example.com -r/--recipient user2@example.com encrypted.txt.gpg
```




## Cleanup



### Log Files

```
$ > logfile
Or
$ cat /dev/null > logfile
Or
$ dd if=/dev/null of=logfile
Or
$ truncate logfile --size 0
```



### .bash_history

- [https://askubuntu.com/a/832345](https://askubuntu.com/a/832345)

```
$ cat /dev/null > ~/.bash_history && history -c && exit
$ history -c && history -w && exit
$ rm -f ~/.bash_history && kill -9 $$
```



### .zsh_history

```
$ cat /dev/null > ~/.zsh_history && history -p && exit
$ history -c && history -w && exit
$ rm -f ~/.zsh_history && kill -9 $$
```




## Secure Delete

```
$ shred -zvu -n7 /path/to/file
$ find /path/to/dir -type f -exec shred -zvu -n7 {} \;
$ shred -zv -n0 /dev/sdc1
```




## Recover Deleted Files

```
$ sudo grep -i -a -B100 -A100 'file contents to find' /dev/sda1 > recovered.bin
$ strings recovered.bin
```




## Partitions

{% embed url="https://youtu.be/QSpGaeHlkoE" %}

List devices:

```
$ lsblk
$ sudo fdisk -l
$ df -h
```

Manage partitions:

```
$ sudo fdisk /dev/sd??
```

Format:

```
$ sudo umount /dev/sd??
$ sudo mkfs.<type> -F 32 -I /dev/sd?? -n VOLUME-NAME
type: 'msdos' (=fat32), 'ntfs'
```




## Floppy

```
$ mcopy -i floppy.img 123.txt ::123.txt
$ mdel -i floppy.img 123.TXT
```




## Checksums

Compare file hashes:

```
$ md5sum /path/to/abc.txt | awk '{print $1, "/path/to/cba.txt"}' > /tmp/checksum.txt
$ md5sum -c /tmp/checksum.txt
```

Compare directory hashes:

```
$ hashdeep -c md5 -r /path/to/dir1 > dir1hashes.txt
$ hashdeep -c md5 -r -X -k dir1hashes.txt /path/to/dir2
```




## Permissions

Set defaults for files:

```
$ find . -type f -exec chmod 644 {} \;
```

Set defaults for directories:

```
$ find . -type d -exec chmod 755 {} \;
```




## Fix Linux Freezes while Copying

```
$ sudo crontab -l | { cat; echo '@reboot echo $((16*1024*1024)) > /proc/sys/vm/dirty_background_bytes'; } | crontab -
$ sudo crontab -l | { cat; echo '@reboot echo $((48*1024*1024)) > /proc/sys/vm/dirty_bytes'; } | crontab -
```




## Kernel

Remove old kernels:

```
$ dpkg -l linux-image-\* | grep ^ii
$ kernelver=$(uname -r | sed -r 's/-[a-z]+//')
$ dpkg -l linux-{image,headers}-"[0-9]*" | awk '/ii/{print $2}' | grep -ve $kernelver
$ sudo apt-get purge $(dpkg -l linux-{image,headers}-"[0-9]*" | awk '/ii/{print $2}' | grep -ve "$(uname -r | sed -r 's/-[a-z]+//')")
```




## Xfce4

Install `xfce4`:

```
$ sudo apt update
$ sudo apt upgrade -y
$ sudo apt install xfce4 xfce4-terminal gtk2-engines-pixbuf -y
```




## GIFs

```
$ sudo apt install peek -y
Or
$ sudo apt install byzanz xdotool -y
$ xdotool getmouselocation
$ byzanz-record --duration=15 --x=130 --y=90 --width=800 --height=500 ~/Desktop/out.gif
```




## NTP

```
$ sudo apt purge ntp -y
$ sudo timedatectl set-timezone Europe/Moscow
$ sudo vi /etc/systemd/timesyncd.conf
NTP=0.ru.pool.ntp.org 1.ru.pool.ntp.org 2.ru.pool.ntp.org 3.ru.pool.ntp.org
$ sudo service systemd-timesyncd restart
$ sudo timedatectl set-ntp true
$ timedatectl status
$ service systemd-timesyncd status
$ service systemd-timedated status
```

1. [https://feeding.cloud.geek.nz/posts/time-synchronization-with-ntp-and-systemd/](https://feeding.cloud.geek.nz/posts/time-synchronization-with-ntp-and-systemd/)
2. [http://billauer.co.il/blog/2019/01/ntp-systemd/](http://billauer.co.il/blog/2019/01/ntp-systemd/)




## ImageMagick

XOR 2 images:

```
$ convert img1.png img2.png -fx "(((255*u)&(255*(1-v)))|((255*(1-u))&(255*v)))/255" img_out
```




## Utilities Syntax



### tar


#### .tar

Pack:

```
tar -cvf directory.tar directory
```

Unpack:

```
tar -xvf directory.tar
```


#### .tar.gz

Pack:

```
tar -cvzf directory.tar.gz directory
```

Unpack:

```
tar -xvzf directory.tar.gz
```


#### .tar.bz

Pack:

```
tar -cvjf directory.tar.bz directory
```

Unpack:

```
tar -xvjf directory.tar.bz
```



### scp

Local file to a remote system:

```
$ scp [-P 2222] file.txt snovvcrash@10.10.13.37:/remote/directory
```

Remote file to a local system:

```
$ scp [-P 2222] snovvcrash@10.10.13.37:/remote/file.txt /local/directory
```



### 7z

Encrypt and pack all files in directory::

```
$ 7z a packed.7z -mhe -p"p4sSw0rD" *
```

Decrypt and unpack:

```
$ 7z e packed.7z -p"p4sSw0rD"
```

Best compression:

```
$ 7z a -t7z -m0=lzma -mx=9 -mfb=64 -md=32m -ms=on files.7z files/
```



### grep / find / sed

Recursive grep:

```
$ grep -nwr 'pattern' /path/to/dir
```

Recursive find and replace:

```
$ find . -type f -name "*.txt" -exec sed -i'' -e 's/\<foo\>/bar/g' {} +
```

Exec `strings` and grep on the result (with filenames):

```
$ find . -type f -print -exec sh -c 'strings $1 | grep -i -n "signature"' sh {} \;
```

Find and `xargs` grep the results:

```
$ find . -type f -print0 | xargs -0 grep <PATTERN>
```

Find and `xargs` less/grep the results:

```
$ export LESS="-R -i"
$ find . -type f -name "*.txt" -print0 | xargs -0 -I{} sh -c 'cat "{}"; echo' | less
```

Enhanced variant using parallel and tre-agrep:

```
$ find . -type f -name "*.txt" | parallel tre-agrep -H --color mystring {} -iE2
```



### readlink

Get absolute path of a file:

```
$ readlink -f somefile.txt
```



### paste

Concatenate text files with a delimeter line by line:

```
$ paste -d':' a.txt b.txt > c.txt
```



### tmux

Send a bunch of lines to a tmux pane:

```
$ tmux run 'echo #{pane_id}'
$ cat files.txt | while read; do tmux send -t '%1' "$REPLY"; sleep 5; done
```



### dpkg

```
$ dpkg -s <package_name>
$ dpkg-query -W -f='${Status}' <package_name>
$ OUT="dpkg-query-$(date +'%FT%H%M%S').csv"; echo 'package,version' > ${OUT} && dpkg-query -W -f '${Package},${Version}\n' >> ${OUT}
```



### veracrypt

* [https://www.veracrypt.fr/en/Downloads.html](https://www.veracrypt.fr/en/Downloads.html)

```
 # Mount volume
$ veracrypt -t --pim=0 --keyfiles='' --protect-hidden=no /home/snovvcrash/SecretVolume.dat /mnt
 # Unmount all
$ veracrypt -d
```



### openconnect


#### GlobalProtect

Connect:

```
$ sudo openconnect --protocol=gp gp.megacorp.com -u snovvcrash
```

Bypass HIP:

* [https://www.infradead.org/openconnect/hip.html](https://www.infradead.org/openconnect/hip.html)
* [https://gitlab.com/openconnect/openconnect/blob/master/trojans/hipreport.sh](https://gitlab.com/openconnect/openconnect/blob/master/trojans/hipreport.sh)

```
PS > Rename-Item "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGpHip.exe" "PanGpHip.exe.bak"
PS > Rename-Item "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGpHipMp.exe" "PanGpHipMp.exe.bak"
PS > Rename-Item "C:\Program Files\Palo Alto Networks\GlobalProtect\wa_3rd_party_host_64.exe" "wa_3rd_party_host_64.exe.bak"
```




## LAMP

* [https://stackoverflow.com/a/46908573](https://stackoverflow.com/a/46908573)

```
 # PHP
$ sudo add-apt-repository ppa:ondrej/php -y
$ sudo apt update
$ sudo apt install php7.2 -y
$ sudo apt install php7.2-curl php7.2-gd php7.2-json php7.2-mbstring -y

 # Apache
$ sudo apt install apache2 libapache2-mod-php7.2 -y
$ sudo service apache2 restart

 # MySQL
$ sudo apt install mysql-server php7.2-mysql
$ sudo mysql_secure_installation
$ service mysql restart

 # Test
$ sudo sh -c 'echo "<?php phpinfo(); ?>" > phpinfo.php'
-> http://127.0.0.1/phpinfo.php
```




## Fun



### CMatrix

```
$ sudo apt-get install cmatrix
```



### screenfetch

```
$ wget -O screenfetch https://raw.github.com/KittyKatt/screenFetch/master/screenfetch-dev
$ chmod +x screenfetch
$ sudo mv screenfetch /usr/bin
```
