# DHCP Server & Linux Hotspot

- [https://luemmelsec.github.io/I-got-99-problems-but-my-NAC-aint-one/](https://luemmelsec.github.io/I-got-99-problems-but-my-NAC-aint-one/)
- [https://learn.adafruit.com/setting-up-a-raspberry-pi-as-a-wifi-access-point/install-software](https://learn.adafruit.com/setting-up-a-raspberry-pi-as-a-wifi-access-point/install-software)

Install stuff:

```
sudo apt install isc-dhcp-server hostapd -y
sudo systemctl enable isc-dhcp-server
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
```

Configure DHCP:

{% code title="/etc/dhcp/dhcpd.conf" %}
```
option domain-name "local";
option domain-name-servers 8.8.8.8, 8.8.4.4;
default-lease-time 600;
max-lease-time 7200;
subnet 192.168.200.0 netmask 255.255.255.0 {
  range 192.168.200.2 192.168.200.20;
  option subnet-mask 255.255.255.0;
  option broadcast-address 192.168.200.255;
}
```
{% endcode %}

Configure hotspot:

{% code title="/etc/hostapd/hostapd.conf" %}
```
interface=wlan0
driver=nl80211
ssid=LinuxHotspot
hw_mode=g
channel=11
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wpa=2
wpa_passphrase=Passw0rd!
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
wpa_group_rekey=86400
ieee80211n=1
wme_enabled=1
```
{% endcode %}

Configure interface (+ set the iface name in `/etc/default/isc-dhcp-server`):

{% code title="/etc/network/interfaces" %}
```
iface wlan0 inet static
  address 192.168.200.1
  netmask 255.255.255.0
```
{% endcode %}

Set static IP on the interface:

```
sudo ifconfig wlan0 down
sudo ifconfig wlan0 192.168.200.1
sudo ifconfig wlan0 up
```

Restart the services:

```
$ sudo service isc-dhcp-server restart
$ sudo service hostapd restart
```
