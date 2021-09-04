# Hyper-V

* [https://xakep.ru/2017/08/09/hyper-v-internals/](https://xakep.ru/2017/08/09/hyper-v-internals/)

Enable feature:

```
PS > Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```




## Sharing VPN

* [https://win10.guru/hyper-v-virtual-machine-use-host-vpn-connection/](https://win10.guru/hyper-v-virtual-machine-use-host-vpn-connection/)




## Enhanced Session Mode

* [https://techcommunity.microsoft.com/t5/virtualization/sneak-peek-taking-a-spin-with-enhanced-linux-vms/ba-p/382415](https://techcommunity.microsoft.com/t5/virtualization/sneak-peek-taking-a-spin-with-enhanced-linux-vms/ba-p/382415)
* [https://www.kali.org/docs/virtualization/install-hyper-v-guest-enhanced-session-mode/](https://www.kali.org/docs/virtualization/install-hyper-v-guest-enhanced-session-mode/)

1. `sudo apt install hyperv-daemons`
2. `kali-tweaks`
3. "Configure the system for Hyper-V enhanced session mode" > Shut down VM.
4. `Set-VM "Kali Linux" -EnhancedSessionTransportType HVSocket`
5. Power up VM.
