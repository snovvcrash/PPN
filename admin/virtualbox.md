# VirtualBox




## DHCP

Configure DHCP in VBox:

```
Cmd > "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" dhcpserver add --netname intnet --ip 10.0.1.1 --netmask 255.255.255.0 --lowerip 10.0.1.101 --upperip 10.0.1.254 --enable
```




## Shared Folders

```
$ sudo usermod -aG vboxsf `whoami`
$ sudo reboot  # or re-login
```




## Dirty Network Configurations

Manually:

```
$ sudo service NetworkManager stop
$ sudo ifconfig 
$ sudo ifconfig eth0 10.10.13.37 netmask 255.255.255.0
$ sudo route add default gw 10.10.13.1 dev eth0
$ sudo route -n
$ sudo vi /etc/resolv.conf 
$ ping 8.8.8.8
$ nslookup ya.ru
$ sudo systemctl enable ssh --now
```

Route inner traffic to eth0 (lan), internet to wlan0 (wan):

```
$ sudo route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.0.1     0.0.0.0         UG    100    0        0 eth0
0.0.0.0         172.20.10.1     0.0.0.0         UG    600    0        0 wlan0
172.20.10.0     0.0.0.0         255.255.255.240 U     600    0        0 wlan0
192.168.0.0     0.0.0.0         255.255.255.0   U     100    0        0 eth0

$ sudo ip route add 192.168.0.0/16 via 192.168.0.1 metric 100 dev eth0
$ sudo ip route add 172.16.0.0/12 via 192.168.0.1 metric 100 dev eth0
$ sudo ip route add 10.0.0.0/8 via 192.168.0.1 metric 100 dev eth0
$ sudo ip route del 0.0.0.0/0 via 192.168.0.1 dev eth0

$ sudo route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         172.20.10.1     0.0.0.0         UG    600    0        0 wlan0
10.0.0.0        192.168.0.1     255.0.0.0       UG    100    0        0 eth0
172.16.0.0      192.168.0.1     255.240.0.0     UG    100    0        0 eth0
172.20.10.0     0.0.0.0         255.255.255.240 U     600    0        0 wlan0
192.168.0.0     0.0.0.0         255.255.255.0   U     100    0        0 eth0
192.168.0.0     192.168.0.1     255.255.0.0     UG    100    0        0 eth0

$ sudo chattr -i /etc/resolv.conf
$ sudo vi /etc/resolv.conf
...change dns resolve order if necessary...
```



### netplan

`/etc/netplan/*.yaml`:

```
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses: [10.10.13.37/24]
      gateway4: 10.10.13.1
      dhcp4: true
      optional: true
      nameservers:
        addresses: [8.8.8.8,8.8.4.4]
```

```
$ sudo service NetworkManager stop
$ sudo netplan apply
```
