# Quick Configurations




## Static Config



### Manually

```
$ sudo service NetworkManager stop
$ ifconfig 
$ sudo ifconfig eth0 10.10.13.37 netmask 255.255.255.0
$ sudo route add default gw 10.10.13.1 dev eth0
$ route -n
$ sudo vi /etc/resolv.conf
domain megacorp.local
search megacorp.local
nameserver 192.168.0.1
$ ping 8.8.8.8
$ nslookup ya.ru
$ sudo systemctl enable ssh --now
```



### resolvconf

* [https://unix.stackexchange.com/questions/128220/how-do-i-set-my-dns-when-resolv-conf-is-being-overwritten](https://unix.stackexchange.com/questions/128220/how-do-i-set-my-dns-when-resolv-conf-is-being-overwritten)

```
$ sudo apt install resolvconf
$ sudo vi /etc/resolvconf/resolv.conf.d/base
$ sudo resolvconf -u
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

Apply:

```
$ sudo service NetworkManager stop
$ sudo netplan apply
```




## Inner and Outer Traffic

Route inner traffic to eth0 (lan), Internet to wlan0 (wan):

```
$ route -n
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

$ route -n
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




## Wrap All Traffic into VPN in Windows

Check the name of VPN interface (`Virtual Ethernet Adapter`):

```
Cmd > ipconfig /all

Адаптер Ethernet Ethernet 2:

   DNS-суффикс подключения . . . . . :
   Описание. . . . . . . . . . . . . : Virtual Ethernet Adapter
   ...
   IPv4-адрес. . . . . . . . . . . . : 192.168.100.181(Основной)
```

Checks its id (`16`, it's shown in decimal):

```
Cmd > route print -4
===========================================================================
Список интерфейсов
  16...00 ff 00 ff 00 ff ......Virtual Ethernet Adapter
```

Add a static route to wrap all traffic into the VPN gateway. To achieve that specify VPN interface id in hexadecimal (`0x10` in this example) and set higher priority for this route (i.e., lower metric) than default gateway route has:

```
Cmd > route add 0.0.0.0 mask 0.0.0.0 192.168.100.1 metric 7 if 0x10
Cmd > route print -4
...
IPv4 таблица маршрута
===========================================================================
Активные маршруты:
Сетевой адрес           Маска сети      Адрес шлюза         Интерфейс   Метрика
          0.0.0.0          0.0.0.0      192.168.0.1     192.168.0.101       25
          0.0.0.0          0.0.0.0    192.168.100.1   192.168.100.181        7
```

To delete the route run:

```
Cmd > route add 0.0.0.0 mask 0.0.0.0 192.168.100.1
```
