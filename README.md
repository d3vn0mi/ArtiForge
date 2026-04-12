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

[![Version](https://img.shields.io/badge/version-0.6.0-blue?style=flat-square)](ROADMAP.md)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](setup.py)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?style=flat-square)](Dockerfile)
[![Author](https://img.shields.io/badge/by-D3vn0mi-red?style=flat-square)](https://github.com/D3vn0mi)

</div>

---

ArtiForge generates realistic Windows event logs and supporting file artifacts from a declarative YAML specification. Drop the output into Elasticsearch/Kibana or open it directly in Windows Event Viewer — no manual crafting required.

**Channels:** Security · System · Sysmon · PowerShell · Application · WMI  
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
| `check --lab <id>` | Run detection rules and report which fire (coverage %) |
| `diff --lab <a> --other <b>` | Compare two lab bundles: event counts, phases, EIDs |
| `graph --lab <id>` | Show ProcessGuid / LogonId correlation chains |
| `navigator --lab <id>` | Export MITRE ATT&CK Navigator layer JSON |
| `coverage` | Print a techniques x labs coverage matrix |
| `serve` | Launch the web UI (requires `pip install artiforge[web]`) |
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

# Deterministic output (same seed = identical output each run)
./artiforge.sh generate --lab uc3 --seed 42

# Add organic timestamp jitter (+/- N seconds per event)
./artiforge.sh generate --lab uc3 --jitter 5

# Max-realism: strip the labels.phase_id / labels.phase_name block from NDJSON
./artiforge.sh generate --lab uc3 --no-meta

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

| ID | Name | Techniques | Phases | Noise |
|----|------|------------|--------|-------|
| `uc3` | Egg-Cellent Resume | LOLBAS · Cloudflared C2 · Veeam CVE-2023-27532 | 5 | - |
| `uc3n` | Egg-Cellent Resume (Noisy) | Same attack as UC3 | 5 | ~143 events |

More labs planned — see [ROADMAP.md](ROADMAP.md).

### Supported Event IDs

| Channel | Log | EIDs |
|---------|-----|------|
| `Security` | Security | 4624 4625 4634 4648 4656 4657 4663 4670 4672 4688 4698 4720 4723 4724 4725 4726 4732 4768 4769 4771 4776 4946 4947 5156 5157 |
| `System` | System | 7036 7045 |
| `Sysmon` | Microsoft-Windows-Sysmon/Operational | 1 3 5 7 8 10 11 12 13 14 17 18 22 23 25 |
| `Application` | Application | 1 |
| `PowerShell` | Microsoft-Windows-PowerShell/Operational | 4103 4104 |
| `WMI` | Microsoft-Windows-WMI-Activity/Operational | 5857 5860 5861 |

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
# (full guide: docs/LAB_AUTHORING_GUIDE.md)

# Validate schema and EID support
./artiforge.sh validate --lab-path /path/to/uc4-kerberoast/lab.yaml

# Generate
./artiforge.sh generate --lab-path /path/to/uc4-kerberoast/lab.yaml
```

For the complete lab authoring reference — YAML fields, event patterns, timing model, and troubleshooting — see **[docs/LAB_AUTHORING_GUIDE.md](docs/LAB_AUTHORING_GUIDE.md)**.

**VS Code:** install the Red Hat YAML extension — `.vscode/settings.json` wires the JSON Schema automatically so every field autocompletes with inline docs.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full plan.

| Milestone | Focus | Status |
|-----------|-------|--------|
| **v0.1** | Foundation — YAML labs, CLI, Docker, 28 EIDs | Done |
| **v0.2** | Event coverage — Kerberos, object access, Sysmon 5-25, WMI | Done |
| **v0.3** | Realism — background noise, `--seed`, `--jitter`, beacon jitter | Done |
| **v0.4** | Lab tooling — `check`, `diff`, `graph`, `validate --strict` | Done |
| **v0.5** | MITRE ATT&CK integration, Navigator layers, web UI | Done |
| **v0.6** | Kibana realism — ECS `labels.*` namespace, `--no-meta` flag | Done |
| **v0.9** | Distribution — PyPI, CI matrix, GHCR image, signed releases | Planned |
| **v1.0** | Scenario library — 7 new labs (Kerberoasting, ransomware, etc.) | Planned |

---

## License

[MIT](LICENSE) · Built by [D3vn0mi](https://github.com/D3vn0mi)
