# Networking

* [https://linkmeup.ru/blog/11.html](https://linkmeup.ru/blog/11.html)

## Quick & Dirty Configurations

### Static Config

#### Manually

```text
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

#### netplan

`/etc/netplan/*.yaml`:

```text
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

```text
$ sudo service NetworkManager stop
$ sudo netplan apply
```

### Routing

#### Inner and Outer Traffic

Route inner traffic to eth0 \(lan\), Internet to wlan0 \(wan\):

```text
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

#### VM as a Router

* [https://0xdf.gitlab.io/2021/05/04/networking-vms-for-htb.html](https://0xdf.gitlab.io/2021/05/04/networking-vms-for-htb.html)

Configure traffic routing and NAT from a Windows host \(192.168.0.101, eth0\) through a Linux VM \(192.168.0.181, eth1 bridged interface\) to VPN \(10.10.10.0/24, tun0\).

Enable IP forwarding on Linux VM:

```text
$ sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
```

Create iptables rules to do the forwarding on Linux VM:

```text
$ sudo iptables -A FORWARD -i tun0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
$ sudo iptables -A FORWARD -i eth1 -o tun0 -j ACCEPT
```

For the purpose of redirecting NEW connections from Linux tun0 to Windows host I can set socat on a needed port as a quick solution \(actually it's not necessary for this routing task\):

```text
$ sudo socat TCP-LISTEN:1337,fork TCP:192.168.0.101:1337
```

Create iptables rules to do NAT on Linux VM:

```text
$ sudo iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o tun0 -j MASQUERADE
```

Add a route to Linux VM on Windows host:

```text
Cmd > route add 10.10.10.0 mask 255.255.255.0 192.168.0.181
```

#### Wrap All Traffic into VPN in Windows

Check the name of VPN interface \(`Virtual Ethernet Adapter`\):

```text
Cmd > ipconfig /all

Адаптер Ethernet Ethernet 2:

   DNS-суффикс подключения . . . . . :
   Описание. . . . . . . . . . . . . : Virtual Ethernet Adapter
   ...
   IPv4-адрес. . . . . . . . . . . . : 192.168.100.181(Основной)
```

Checks its id \(`16`, it's shown in decimal\):

```text
Cmd > route print -4
===========================================================================
Список интерфейсов
  16...00 ff 00 ff 00 ff ......Virtual Ethernet Adapter
```

Add a static route to wrap all traffic into the VPN gateway. To achieve that specify VPN interface id in hexadecimal \(`0x10` in this example\) and set higher priority for this route \(i.e., lower metric\) than default gateway route has:

```text
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

```text
Cmd > route add 0.0.0.0 mask 0.0.0.0 192.168.100.1
```

## Log Connections

### tcpdump

Register ICMP replies from 10.10.13.38:

```text
$ sudo tcpdump -n -i tun0 -XSs 0 'src 10.10.13.38 and icmp[icmptype]==8'
```

### iptables

Add rule to register **new** \(does not watch for related, established\) connections to your machine:

```text
$ sudo iptables -A INPUT -p tcp -m state --state NEW -j LOG --log-prefix "IPTables New-Connection: " -i tun0
```

Check the logs:

```text
$ sudo grep IPTables /var/log/messages
```

Delete rule:

```text
$ sudo iptables -D INPUT -p tcp -m state --state NEW -j LOG --log-prefix "IPTables New-Connection: " -i tun0
```

## Tools

### iptables

* [An In-Depth Guide to iptables, the Linux Firewall - Boolean World](https://www.booleanworld.com/depth-guide-iptables-linux-firewall/)

List rules in all chains \(default table is _filter_, there are _mangle_, _nat_ and _raw_ tables beside it\):

```text
$ sudo iptables -L -n --line-numbers [-t filter]
```

Print rules for all chains \(for a specific chains\):

```text
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

