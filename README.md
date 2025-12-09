# proxymydll

`proxymydll` is a Python helper that automates the creation of **DLL proxy stubs** (C++ source files) from an existing DLL.

![Desktop View](/img/proxylogo.png)

It is a fork of:

* **perfect-dll-proxy** by [mrexodia](https://github.com/mrexodia/perfect-dll-proxy)

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

<a href="https://asciinema.org/a/5OqPD3nq6z9GOfhawzFA4Wgu4" target="_blank"><img src="https://asciinema.org/a/5OqPD3nq6z9GOfhawzFA4Wgu4.svg" /></a>

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



