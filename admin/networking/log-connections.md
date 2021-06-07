# Log Connections




## tcpdump/tshark

Register ICMP replies from 10.10.13.38:

```
$ sudo tcpdump -n -i tun0 -XSs 0 'src 10.10.13.38 and icmp[icmptype]==8'
```




## iptables

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
