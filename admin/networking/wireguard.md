# WireGuard

- [https://upcloud.com/resources/tutorials/get-started-wireguard-vpn](https://upcloud.com/resources/tutorials/get-started-wireguard-vpn)




## Server

Quick start:

```
$ sudo apt install wireguard
$ sudo vi /etc/sysctl.conf
net.ipv4.ip_forward=1
$ sudo sysctl -p
$ cd /etc/wireguard && umask 077
$ mkdir clients && cd clients && umask 077 && cd -
$ wg genkey | tee privatekey | wg pubkey > publickey
```

Control:

```
$ wg-quick up wg0
$ wg show
```

Enable at boot:

```
$ systemctl enable wg-quick@wg0
$ sudo modprobe wireguard
```

Configuration template:

{% code title="/etc/wireguard" %}
```
[Interface]
PrivateKey = <SERVER_PRIVATEKEY>
Address = 172.16.1.1/24
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
ListenPort = 41194

[Peer]
## Client1
PublicKey = <CLIENT1_PUBLICKEY>
AllowedIPs = 172.16.1.2/32

[Peer]
## Client2
PublicKey = <CLIENT2_PUBLICKEY>
AllowedIPs = 172.16.1.3/32
```
{% endcode %}




## Client

Generate keys:

```
$ $ wg genkey | tee client1 | wg pubkey > client1.pub
```

Configuration template:

{% code title="client.template" %}
```
[Interface]
PrivateKey = <CLIENT1_PRIVATEKEY>
Address = 172.16.1.2/24
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = <SERVER_PUBLICKEY>
AllowedIPs = 0.0.0.0/0
Endpoint = <SERVER_IP>:41194
PersistentKeepalive = 15
```

Restart the server:

```
$ sudo systemctl restart wg-quick@wg0
```
