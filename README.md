<div align="center">

```
  █████╗ ██████╗ ████████╗██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ██╔══██╗██╔══██╗╚══██╔══╝██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
 ███████║██████╔╝   ██║   ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
 ██╔══██║██╔══██╗   ██║   ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
 ██║  ██║██║  ██║   ██║   ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
 ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

**YAML-driven Windows event artifact generator for cybersecurity training labs**

[![Version](https://img.shields.io/badge/version-0.1.0-blue?style=flat-square)](ROADMAP.md)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](setup.py)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?style=flat-square)](Dockerfile)
[![Author](https://img.shields.io/badge/by-D3vn0mi-red?style=flat-square)](https://github.com/D3vn0mi)

</div>

---

ArtiForge generates realistic Windows event logs and supporting file artifacts from a declarative YAML specification. Drop the output into Elasticsearch/Kibana or open it directly in Windows Event Viewer — no manual crafting required.

**Channels:** Security · System · Sysmon · PowerShell · Application  
**Output:** Windows XML · Elasticsearch NDJSON (ECS-mapped)  
**Artifacts:** LNK · XSL · INF · Scheduled Task XML · Binary stubs

---

## Getting Started

### Docker — recommended, no Python needed

```bash
# 1. Build the image once
docker build -t artiforge:latest .

# 2. Use the wrapper script for everything — output lands in ./artifacts/
./artiforge.sh list-labs
./artiforge.sh generate --lab uc3
./artiforge.sh validate --lab uc3
```

> `artiforge.sh` mounts your current directory into the container and forwards all arguments.
> Generated files are written to `./artifacts/` on your host, owned by your user.

### Python — local install

```bash
pip install -e .
artiforge list-labs
artiforge generate --lab uc3
```

---

## Commands

| Command | Description |
|---------|-------------|
| `list-labs` | List all available labs |
| `info --lab <id>` | Show phases, event counts, and infrastructure |
| `generate --lab <id>` | Generate all artifacts for a lab |
| `validate --lab <id>` | Schema check + EID coverage scan, no files written |
| `new-lab --id <id>` | Scaffold a new lab directory from the built-in template |
| `schema` | Print or save the JSON Schema for IDE autocompletion |

### Key Flags

```bash
# Preview without writing any files
./artiforge.sh generate --lab uc3 --dry-run

# Run specific phases only
./artiforge.sh generate --lab uc3 --phases 1,4

# Override the base timestamp
./artiforge.sh generate --lab uc3 --base-time "2026-06-01T08:30:00Z"

# Use a lab YAML from outside the built-in directory
./artiforge.sh generate --lab-path /path/to/lab.yaml
./artiforge.sh validate --lab-path /path/to/lab.yaml
```

---

## Output

```
artifacts/
└── uc3_20260219_091200/
    ├── events/
    │   ├── WIN-WS1_Security.xml        ← Windows Event Viewer / wevtutil
    │   ├── WIN-WS1_Sysmon.xml
    │   ├── WIN-WS1_System.xml
    │   ├── WIN-WS1_Application.xml
    │   ├── WIN-BACKUP1_Security.xml
    │   ├── WIN-WS2_Security.xml
    │   └── WIN-WS2_Sysmon.xml
    ├── elastic/
    │   └── bulk_import.ndjson          ← Elasticsearch bulk API
    ├── files/
    │   ├── phase01/                    ← LNK lure, XSL stylesheet, INF
    │   ├── phase02/                    ← Scheduled task XML
    │   └── phase04/                    ← Cloudflared binary stub
    └── IMPORT.md                       ← Step-by-step import instructions
```

---

## Labs

| ID | Name | Techniques | Phases |
|----|------|------------|--------|
| `uc3` | Egg-Cellent Resume | LOLBAS · Cloudflared C2 · Veeam CVE-2023-27532 | 5 |

More labs planned — see [ROADMAP.md](ROADMAP.md).

### Supported Event IDs

| Channel | Log | EIDs |
|---------|-----|------|
| `Security` | Security | 4624 4625 4634 4648 4672 4688 4698 4720 4732 4776 |
| `System` | System | 7036 7045 |
| `Sysmon` | Microsoft-Windows-Sysmon/Operational | 1 3 11 13 22 |
| `Application` | Application | 1 |
| `PowerShell` | Microsoft-Windows-PowerShell/Operational | 4103 4104 |

### UC3 Event Coverage

| Phase | Offset | Events |
|-------|--------|--------|
| 01 — Initial Access | T+0m | Sysmon 11 · 4688 · Sysmon 1 · ie4uinit → msxsl → cmd chain |
| 02 — Persistence | T+30m | Sysmon 11 · 4688 · Sysmon 1 · 4698 · Sysmon 13 |
| 03 — Veeam Pivot | T+60m | Sysmon 3 (TCP 9401) · wmic recon · 4720 · 4732 · 4648 |
| 04 — Cloudflared | T+90m | Sysmon 11 · sc create/start · 7045 · Sysmon 3 ×5 · App 1 |
| 05 — Lateral Movement | T+120m | 4648 · 4624 Type 10 · Compress-Archive · Sysmon 11 · 4634 |

### MITRE ATT&CK

`T1204.002` `T1566.001` `T1218` `T1218.010` `T1053.005` `T1210` `T1136.001` `T1078` `T1572` `T1543.003` `T1036.004` `T1021.001` `T1550.002` `T1560.001`

---

## Creating a New Lab

```bash
# Scaffold from the built-in template
./artiforge.sh new-lab --id uc4-kerberoast --name "Kerberoasting Lab" --output /work

# Edit — every field that needs changing is marked FIXME
# (full guide: artiforge/labs/_template/DEVELOPMENT.md)

# Validate schema and EID support
./artiforge.sh validate --lab-path /path/to/uc4-kerberoast/lab.yaml

# Generate
./artiforge.sh generate --lab-path /path/to/uc4-kerberoast/lab.yaml
```

**VS Code:** install the Red Hat YAML extension — `.vscode/settings.json` wires the JSON Schema automatically so every field autocompletes with inline docs.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full plan.

| Milestone | Focus |
|-----------|-------|
| **v0.2** | Event coverage — Kerberos, object access, Sysmon 5/7/8/10, WMI |
| **v0.3** | Realism — background noise, timestamp jitter, multi-user sessions |
| **v0.4** | Lab tooling — detection checks, strict validation, schema versioning |
| **v1.0** | Lab ecosystem — 10+ scenarios, ATT&CK Navigator, web UI, PyPI |
| **v1.1** | Export integrations — Splunk HEC, Sentinel, QRadar, CEF |

---

## License

[MIT](LICENSE) · Built by [D3vn0mi](https://github.com/D3vn0mi)
