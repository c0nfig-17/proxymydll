# proxymydll

`proxymydll` is a Python helper that automates the creation of **DLL proxy stubs** (C++ source files) from an existing DLL.

![Desktop View](/proxylogo.png)

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


