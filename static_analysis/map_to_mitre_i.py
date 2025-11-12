# TODO: Fully flush this out using PE studio as an example and then moving to generation from MITRE itself

# ---------------------------
# Simple mapping knowledge base
# ---------------------------
# Each technique has:
# - name: textual name
# - indicators: list of indicator rules each being a tuple (type, pattern, weight, note)
#    type in {"import", "string", "yara", "section", "vt_label"}
# - Examples and comments help analyst understand mapping
MITRE_MAP = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "indicators": [
            ("string", r"powershell.exe|pwsh.exe|Invoke-Expression|IEX\b", 40, "PowerShell usage"),
            ("string", r"cmd\.exe|/c |/k ", 25, "cmd execution strings"),
            ("import", r"CreateProcess|ShellExecuteEx|WinExec", 30, "process creation APIs"),
            ("yara", r"PowerShell", 35, "YARA rule mentioning PowerShell"),
        ],
        "description": "Execution via scripting/command interpreters."
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "indicators": [
            ("string", r"http[s]?://|ftp://", 30, "URL evidence"),
            ("import", r"URLDownloadToFile|InternetReadFile|HttpSendRequest|WinHttp", 35, "network download APIs"),
            ("yara", r"Download|Dropper", 40, "YARA suggests dropper behavior"),
        ],
        "description": "Transferring tools or files from external systems into victims."
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "indicators": [
            ("import", r"LSA|LogonUser|CredEnumerate|NetUserGetInfo|NtQuerySystemInformation", 40, "credential or system info APIs"),
            ("string", r"sekurlsa|lsass|SAM|NTDS", 40, "strings referencing credential stores"),
            ("yara", r"mimikatz|credential|lsass", 45, "YARA indicates credential dumping tools"),
        ],
        "description": "Obtaining credentials from OS stores or process memory."
    },
    "T1055": {
        "name": "Process Injection",
        "indicators": [
            ("import", r"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|NtUnmapViewOfSection|SetWindowsHookEx", 40, "common injection APIs"),
            ("yara", r"injection|ReflectiveLoader", 40, "YARA rules for injection"),
            ("string", r"LoadLibraryA|GetProcAddress", 15, "dynamic loading functions"),
        ],
        "description": "Injection of code into other processes."
    },
    "T1574": {
        "name": "Hijack Execution Flow / DLL Search Order Hijacking",
        "indicators": [
            ("section", r"\.rdata|\.data|\.rsrc", 10, "suspicious resource manipulation"),
            ("import", r"LoadLibrary|SetWindowsHookEx", 25, "DLL loading / hooks"),
            ("yara", r"dll\s*hijack|dllsearch", 40, "YARA indicates DLL hijack"),
        ],
        "description": "Hijacking exe/dll load paths or hooks for persistence or code execution."
    },
    "T1204": {
        "name": "User Execution",
        "indicators": [
            ("string", r"open|click|run this|Double-click|README", 20, "social engineering indicators in strings"),
            ("yara", r"phish|social", 35, "YARA detecting social-engineering"),
        ],
        "description": "Tricking user to execute or open malicious content."
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "indicators": [
            ("import", r"InternetOpenUrl|HttpSendRequest|WinHttp|socket|send|recv", 30, "networking APIs"),
            ("string", r"HTTP/1\.[01]|POST |GET /|User-Agent:|Host:", 25, "HTTP artifacts in strings"),
            ("yara", r"HTTP|C2|beacon", 35, "YARA references C2/HTTP beaconing"),
        ],
        "description": "Using application layer protocols for C2 and data exfiltration."
    }
}
