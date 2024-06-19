# Networking

- [https://linkmeup.ru/blog/11.html](https://linkmeup.ru/blog/11.html)
- [https://habr.com/ru/post/307252/](https://habr.com/ru/post/307252/)
- [https://kbespalov.medium.com/виртуальные-сетевые-устройства-в-linux-linux-bridge-7e0e887edd01](https://kbespalov.medium.com/виртуальные-сетевые-устройства-в-linux-linux-bridge-7e0e887edd01)




## Log Connections



### tcpdump / tshark

Register ICMP replies from 10.10.13.38:

```
$ sudo tcpdump -n -i eth0 -XSs 0 'src 10.10.13.38 and icmp[icmptype]==8'
```

Redirect to text file adding timestamps:

```
$ sudo tcpdump -i eth0 -tttt -l icmp | tee icmp.txt
```



### iptables

Add rule to register **new** (does not watch for related, established) connections to your machine:

```
$ sudo iptables -A INPUT -p tcp -m state --state NEW -j LOG --log-prefix "IPTables New-Connection: " -i tun0
```

Check the logs:

```
$ sudo grep IPTables /var/log/messages
```

Delete rule:

```
$ sudo iptables -D INPUT -p tcp -m state --state NEW -j LOG --log-prefix "IPTables New-Connection: " -i tun0
```




## Tools



### dhclient

Release the current lease on `eth0` and obtain a fresh IP via DHCP in Linux:

```
$ sudo dhclient -v -r eth0
$ sudo dhclient -v eth0
```



### iptables

* [https://www.booleanworld.com/depth-guide-iptables-linux-firewall/](https://www.booleanworld.com/depth-guide-iptables-linux-firewall/)
* [https://habr.com/ru/sandbox/18975/](https://habr.com/ru/sandbox/18975/)

List rules in all chains (default table is *filter*, there are *mangle*, *nat* and *raw* tables beside it):

```
$ sudo iptables -L -n --line-numbers [-t filter]
```

Print rules for all chains (for a specific chains):

```
$ sudo iptables -S [INPUT [1]]
```



### fail2ban

* `/etc/fail2ban/filter.d` - filters which turn into *user-defined* fail2ban iptables rules (automatically).

Status:

```
$ sudo service fail2ban status
$ sudo fail2ban-client status
$ sudo fail2ban-client status sshd
```

Unban:

```
$ sudo fail2ban-client unban --all
$ sudo fail2ban-client set sshd unbanip <IP>
```



### OpenVPN

* [https://wiki.calculate-linux.org/openvpn](https://wiki.calculate-linux.org/openvpn)
