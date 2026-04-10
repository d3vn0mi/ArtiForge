"""MITRE ATT&CK technique ID → human-readable name.

Covers techniques used in built-in labs and detection rules.
Extend this dict when adding labs that reference unlisted techniques.
"""

TECHNIQUE_NAMES: dict[str, str] = {
    # ── Initial Access ────────────────────────────────────────────────────────
    "T1190":     "Exploit Public-Facing Application",
    "T1133":     "External Remote Services",
    "T1566":     "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1204":     "User Execution",
    "T1204.002": "User Execution: Malicious File",
    "T1204.004": "User Execution: Malicious Copy and Paste",
    "T1204.005": "User Execution: Malicious Library",

    # ── Execution ─────────────────────────────────────────────────────────────
    "T1059":     "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.010": "Command and Scripting Interpreter: AutoHotkey & AutoIT",
    "T1047":     "Windows Management Instrumentation",
    "T1218":     "System Binary Proxy Execution",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1218.015": "System Binary Proxy Execution: Electron Applications",

    # ── Persistence ───────────────────────────────────────────────────────────
    "T1053":     "Scheduled Task/Job",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1543":     "Create or Modify System Process",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1546":     "Event Triggered Execution",
    "T1546.003": "Event Triggered Execution: Windows Management Instrumentation",
    "T1547":     "Boot or Logon Autostart Execution",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys",

    # ── Privilege Escalation ──────────────────────────────────────────────────
    "T1548":     "Abuse Elevation Control Mechanism",
    "T1548.002": "Abuse Elevation Control Mechanism: Bypass UAC",

    # ── Defense Evasion ───────────────────────────────────────────────────────
    "T1027":     "Obfuscated Files or Information",
    "T1027.013": "Obfuscated Files or Information: Encrypted/Encoded File",
    "T1036":     "Masquerading",
    "T1036.004": "Masquerading: Masquerade Task or Service",
    "T1036.011": "Masquerading: Overwrite Process Arguments",
    "T1055":     "Process Injection",
    "T1055.003": "Process Injection: Thread Execution Hijacking",
    "T1070":     "Indicator Removal",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1112":     "Modify Registry",

    # ── Credential Access ─────────────────────────────────────────────────────
    "T1003":     "OS Credential Dumping",
    "T1003.001": "OS Credential Dumping: LSASS Memory",

    # ── Lateral Movement ──────────────────────────────────────────────────────
    "T1021":     "Remote Services",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1210":     "Exploitation of Remote Services",
    "T1550":     "Use Alternate Authentication Material",
    "T1550.002": "Use Alternate Authentication Material: Pass the Hash",

    # ── Collection ────────────────────────────────────────────────────────────
    "T1560":     "Archive Collected Data",
    "T1560.001": "Archive Collected Data: Archive via Utility",

    # ── Command and Control ───────────────────────────────────────────────────
    "T1071":     "Application Layer Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1090":     "Proxy",
    "T1090.001": "Proxy: Internal Proxy",
    "T1572":     "Protocol Tunneling",

    # ── Exfiltration ──────────────────────────────────────────────────────────
    "T1041":     "Exfiltration Over C2 Channel",

    # ── Impact ────────────────────────────────────────────────────────────────
    "T1486":     "Data Encrypted for Impact",
    "T1490":     "Inhibit System Recovery",

    # ── Identity / Account ────────────────────────────────────────────────────
    "T1078":     "Valid Accounts",
    "T1136":     "Create Account",
    "T1136.001": "Create Account: Local Account",
    "T1098":     "Account Manipulation",
    "T1098.007": "Account Manipulation: Additional Local or Domain Groups",

    # ── Other ─────────────────────────────────────────────────────────────────
    "T1105":     "Ingress Tool Transfer",
    "T1678":     "Delay Execution",
}
