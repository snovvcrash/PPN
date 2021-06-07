# Routing




## VM as a Router

* [https://0xdf.gitlab.io/2021/05/04/networking-vms-for-htb.html](https://0xdf.gitlab.io/2021/05/04/networking-vms-for-htb.html)

Configure traffic routing and NAT from a Windows host (192.168.0.101, eth0) through a Linux VM (192.168.0.181, eth1 bridged interface) to VPN (10.10.10.0/24, tun0).

Enable IP forwarding on Linux VM:

```
$ sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
```

Create iptables rules to do the forwarding on Linux VM:

```
$ sudo iptables -A FORWARD -i tun0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
$ sudo iptables -A FORWARD -i eth1 -o tun0 -j ACCEPT
```

For the purpose of redirecting NEW connections from Linux tun0 to Windows host I can set socat on a needed port as a quick solution (actually it's not necessary for this routing task):

```
$ sudo socat TCP-LISTEN:1337,fork TCP:192.168.0.101:1337
```

Create iptables rules to do NAT on Linux VM:

```
$ sudo iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o tun0 -j MASQUERADE
```

Add a route to Linux VM on Windows host:

```
Cmd > route add 10.10.10.0 mask 255.255.255.0 192.168.0.181
```




## OpenVPN Jump Server

I shall configure an intermediate OpenVPN server to serve as a jump box (1st hop) to connect to the target lab. It's helpful when the target OpenVPN server (2nd hop) doesn't allow to have multiple connections with the same common name (`--duplicate-cn` not set), i.e. using the same client's `.ovpn` profile.

![](/.gitbook/assets/2.png)

Quick OpenVPN server installation:

* [https://www.cyberciti.biz/faq/howto-setup-openvpn-server-on-ubuntu-linux-14-04-or-16-04-lts/](https://www.cyberciti.biz/faq/howto-setup-openvpn-server-on-ubuntu-linux-14-04-or-16-04-lts/)

```
$ sudo apt update
$ wget https://git.io/vpn -O openvpn-install.sh
$ chmod +x openvpn-install.sh
$ sudo bash openvpn-install.sh
```

Check OpenVPN server status:

```
$ sudo service openvpn-server@server status
```

Change server config (`/etc/openvpn/server/server.conf`):

```
 # Allocate a virtual /30 network
topology net30

 # Add as many clients as you need
route 10.8.1.0 255.255.255.0
route 10.8.2.0 255.255.255.0

 # Set a directory to look for clients' configs
client-config-dir ccd
```

Create a directory with clients' configs and set a static IP for clients:

```
$ sudo mkdir /etc/openvpn/server/ccd
$ sudo sh -c 'echo "ifconfig-push 10.8.1.1 10.8.1.2" > /etc/openvpn/server/ccd/kali'
$ sudo sh -c 'echo "ifconfig-push 10.8.1.5 10.8.1.6" > /etc/openvpn/server/ccd/parrot'
$ sudo sh -c 'echo "ifconfig-push 10.8.2.1 10.8.2.2" > /etc/openvpn/server/ccd/ubuntu'
```

For other clients /30 subnets [must be used](https://openvpn.net/community-resources/configuring-client-specific-rules-and-access-policies/) as well:

```
[1,2] [5,6] [9,10] [13,14] [17,18] [21,22] [25,26] [29,30] [33,34] [37,38] [41,42] [45,46] [49,50] [53,54] [57,58] [61,62] [65,66] [69,70] [73,74] [77,78] [81,82] [85,86] [89,90] [93,94] [97,98] [101,102] [105,106] [109,110] [113,114] [117,118] [121,122] [125,126] [129,130] [133,134] [137,138] [141,142] [145,146] [149,150] [153,154] [157,158] [161,162] [165,166] [169,170] [173,174] [177,178] [181,182] [185,186] [189,190] [193,194] [197,198] [201,202] [205,206] [209,210] [213,214] [217,218] [221,222] [225,226] [229,230] [233,234] [237,238] [241,242] [245,246] [249,250] [253,254]
```

Restart OpenVPN server (`tun0`):

```
$ sudo service openvpn-server@server restart
```

Start OpenVPN client (`tun1`):

```
$ nohup sudo openvpn --client --config lab.ovpn &
```

Check interfaces:

```
$ ifconfig tun0
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.8.0.1  netmask 255.255.255.255  destination 10.8.0.2
        inet6 fe80::ca99:1dec:45c1:5d7a  prefixlen 64  scopeid 0x20<link>
        inet6 fddd:1194:1194:1194::1  prefixlen 64  scopeid 0x0<global>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 100  (UNSPEC)
        RX packets 5  bytes 420 (420.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 9  bytes 724 (724.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
$ ifconfig tun1
tun1: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.13.37  netmask 255.255.254.0  destination 10.10.13.37
        inet6 dead:beef:2::10ef  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::bbe3:5b14:117e:4b99  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 100  (UNSPEC)
        RX packets 5  bytes 420 (420.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10  bytes 800 (800.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Configure NAT:

```
 # Source NAT to reach resources from tun0 to tun1
$ sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o tun1 -j SNAT --to-source 10.10.13.37
 # Destination NAT to trigger reverse shells from tun1 to tun0 (separate port ranges for separate clients)
$ sudo iptables -t nat -A PREROUTING -i tun1 -p tcp --dport 6001:7000 -j DNAT --to-destination 10.8.1.1
$ sudo iptables -t nat -A PREROUTING -i tun1 -p tcp --dport 7001:8000 -j DNAT --to-destination 10.8.1.5
$ sudo iptables -t nat -A PREROUTING -i tun1 -p tcp --dport 8001:9000 -j DNAT --to-destination 10.8.2.1
```

Make iptables rules persistent:

```
$ sudo apt install iptables-persistent -y
$ sudo service netfilter-persistent save
```

Add the following directive to client's `.ovpn` config to ignore default gateway redirection:

```
pull-filter ignore "redirect-gateway"
```

Connect to `tun0` as a client (example for the `kali` client) and manually add a route only for traffic you want to go through VPN:

```
$ sudo openvpn kali.ovpn
$ sudo ip route add 10.10.10.0/24 via 10.8.1.2 metric 0 dev tun0
```
