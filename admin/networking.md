# Networking

* [https://linkmeup.ru/blog/11.html](https://linkmeup.ru/blog/11.html)




## Quick & Dirty Configurations



### Static Config


#### Manually

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


#### netplan

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



### Routing


#### Inner and Outer Traffic

Route inner traffic to eth0 (lan), Internet to wlan0 (wan):

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


#### VM as a Router

* [https://0xdf.gitlab.io/2021/05/04/networking-vms-for-htb.html](https://0xdf.gitlab.io/2021/05/04/networking-vms-for-htb.html)

Configure traffic routing and NAT from a Windows host (192.168.0.101, eth0) through a Linux VM (192.168.0.151, eth0 bridged interface) to VPN (10.10.10.0/24, tun0).

Enable IP forwarding on Linux VM:

```
$ sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
```

Create iptables rules to do the forwarding on Linux VM:

```
$ sudo iptables -A FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
$ sudo iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT
```

Create iptables rules to do NAT on Linux VM:

```
$ sudo iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o tun0 -j MASQUERADE
```

Add a route to Linux VM on Windows host:

```
Cmd > route add 10.10.10.0 mask 255.255.255.0 192.168.0.151
```




## Tools



### iptables

* [An In-Depth Guide to iptables, the Linux Firewall - Boolean World](https://www.booleanworld.com/depth-guide-iptables-linux-firewall/)

List rules in all chains (default table is *filter*, there are *mangle*, *nat* and *raw* tables beside it):

```
$ sudo iptables -L -n --line-numbers [-t filter]
```

Print rules for all chains (for a specific chains):

```
$ sudo iptables -S [INPUT [1]]
```



### fail2ban

```bash
 # Filters location which turn into *user-defined* fail2ban iptables rules (automatically)
/etc/fail2ban/filter.d

 # Status
$ sudo service fail2ban status
$ sudo fail2ban-client status
$ sudo fail2ban-client status sshd

 # Unban all
$ sudo fail2ban-client unban --all
```
