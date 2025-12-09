# proxymydll

`proxymydll` is a Python helper that automates the creation of **DLL proxy stubs** (C++ source files) from an existing DLL. It is a fork of * **perfect-dll-proxy** by [mrexodia](https://github.com/mrexodia/perfect-dll-proxy) . In this repository, I modify the original code to automate several functionalities I needed, allowing me to generate my own malicious Proxy DLLs.

<img src="/img/proxylogo.png" alt="Desktop View" width="200">

with extra functionality to:

* Generate a C++ proxy DLL that forwards all exports to the original.
* Inject a **custom command** that runs when the DLL is loaded (`DLL_PROCESS_ATTACH`).
* Optionally **download** a remote script or **download & execute** it using PowerShell.
* Optionally **recursively Base64-encode** the PowerShell payload for `-enc` execution.

> ⚠️ **Disclaimer**
> This tool is intended for **educational, research and authorized red team / penetration testing** purposes only.
> Do **not** use it on systems you do not own or have explicit permission to test.
> You are solely responsible for how you use this code.

---


## Usage
With this script, you can easily automate the process of generating DLLs for malicious use. Using --cmd, you can specify the command to be executed. With --ip, you define a target IP address, and with --down you can download a specific file from that IP. Alternatively, using --downexe, you can download and directly execute it via IEX. <br>
I added an --enc feature that allows you to recursively encode and execute the specified content. For example, with --enc 3, you will execute a PowerShell instance that runs another encoded PowerShell instance, which runs another encoded PowerShell instance, and so on. The goal is to make detection more difficult, although you should keep in mind that in some cases this may actually draw more attention."

```python
usage: proxymydll.py [-h] [--output OUTPUT] [--force-ordinals] [--cmd CMD] [--ip IP] [--down DOWN] [--downexe DOWNEXE] [--enc ENC] dll

Generate a proxy DLL

positional arguments:
  dll                   Path to the DLL to generate a proxy for

options:
  -h, --help            show this help message and exit
  --output, -o OUTPUT   Generated C++ proxy file
  --force-ordinals, -v
  --cmd CMD             Command to execute
  --ip IP               IP for downloads
  --down DOWN           Download file but do NOT execute
  --downexe DOWNEXE     Download AND execute via IEX
  --enc ENC             Recursive Base64 PS encoding depth
```

## Aditional Content
You will have /add directory with secure32.dll as additional resources to easly proxy this dll. You can download for example [OneDrive](https://www.microsoft.com/es-es/microsoft-365/onedrive/download) to proxy the installer.

## Demo
<a href="https://asciinema.org/a/5OqPD3nq6z9GOfhawzFA4Wgu4" target="_blank"><img src="https://asciinema.org/a/5OqPD3nq6z9GOfhawzFA4Wgu4.svg" /></a>

## To-do
- Add to my blog proxymydll demo, usage and theory





