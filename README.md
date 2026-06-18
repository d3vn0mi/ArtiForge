<div align="center">

```
  █████╗ ██████╗ ████████╗██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ██╔══██╗██╔══██╗╚══██╔══╝██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
 ███████║██████╔╝   ██║   ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
 ██╔══██║██╔══██╗   ██║   ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
 ██║  ██║██║  ██║   ██║   ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
 ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

**Cross-platform event artifact generator for cybersecurity training labs**

[![Version](https://img.shields.io/badge/version-1.0.0-blue?style=flat-square)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](pyproject.toml)
[![CI](https://img.shields.io/github/actions/workflow/status/D3vn0mi/ArtiForge/ci.yml?style=flat-square&label=CI)](https://github.com/D3vn0mi/ArtiForge/actions)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?style=flat-square)](Dockerfile)
[![Author](https://img.shields.io/badge/by-D3vn0mi-red?style=flat-square)](https://github.com/D3vn0mi)

</div>

---

ArtiForge generates forensically-sound event logs, filesystem artifacts, and detection rules from declarative YAML lab specifications. Drop the output into Elasticsearch/Kibana, load `.evtx` files in Chainsaw/Hayabusa, or analyze `audit.log` with `ausearch` — no manual event crafting required.

**71 event generators** across 7 channels (Windows + Linux) | **5 export formats** | **Correlated identifiers** | **Sigma detection rules** | **Forensic artifacts**

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Event Correlation** | Related events share LogonId, ProcessGuid, and ProcessId within each phase — trainees can trace sessions across events |
| **Binary EVTX Export** | Pure-Python `evtxforge` library produces `.evtx` files loadable by Chainsaw, Hayabusa, and Windows Event Viewer |
| **Sigma Rule Evaluator** | Lightweight Sigma YAML evaluator (~80% syntax coverage, zero dependencies) with `artiforge check --sigma-dir` |
| **Noise Engine v2** | 8 noise types with temporal profiles (`office_hours`, `24x7_server`, `developer_workstation`) — events cluster around business hours |
| **Linux Auditd** | 7 auditd record types (SYSCALL, EXECVE, PATH, etc.) with raw `audit.log` and ECS NDJSON export |
| **Filesystem Artifacts** | Auto-generated Prefetch (binary `.pf`), Amcache (JSON), and $MFT (JSON) from process execution events |
| **Web Dashboard** | Browser-based scenario browser with timeline visualization, detection coverage, and MITRE ATT&CK mapping |

---

## Getting Started

### Docker (recommended)

```bash
git clone https://github.com/D3vn0mi/ArtiForge.git
cd ArtiForge
docker build -t artiforge:latest .

./artiforge.sh list-labs
./artiforge.sh generate --lab uc3e --format xml,elastic,evtx --seed 42
```

### Python

```bash
pip install -e libs/evtxforge
pip install -e ".[web]"

artiforge list-labs
artiforge generate --lab uc3e --format xml,elastic,evtx --seed 42
```

### Full walkthrough

See **[QUICKSTART.md](QUICKSTART.md)** — spin up Elastic/Kibana, generate artifacts, ingest, and hunt through the events step by step.

---

## Commands

| Command | Description |
|---------|-------------|
| `list-labs` | List all available labs |
| `info --lab <id>` | Show phases, event counts, and infrastructure |
| `generate --lab <id>` | Generate all artifacts for a lab |
| `validate --lab <id> --strict` | Schema check + realism validation |
| `check --lab <id>` | Run detection rules (built-in + Sigma) and report coverage |
| `diff --lab <a> --other <b>` | Compare two lab bundles |
| `graph --lab <id>` | Show ProcessGuid / LogonId correlation chains |
| `navigator --lab <id>` | Export MITRE ATT&CK Navigator layer JSON |
| `coverage` | Techniques x labs coverage matrix |
| `serve` | Launch the web dashboard (requires `pip install artiforge[web]`) |
| `new-lab --id <id>` | Scaffold a new lab from the built-in template |
| `schema` | Print JSON Schema for IDE autocompletion |
| `es-list` | List all ArtiForge indices in Elasticsearch |
| `es-delete <lab_id>` | Delete a scenario's data from Elasticsearch (with confirmation) |
| `es-purge` | Delete ALL ArtiForge indices (with confirmation) |

> `es-list`, `es-delete`, and `es-purge` are shell commands handled by `artiforge.sh` — they run on the host, not inside Docker. Set `ES_URL` if Elasticsearch is not on localhost.

### Key Flags

```bash
./artiforge.sh generate --lab uc3e --format evtx          # Binary EVTX only
./artiforge.sh generate --lab uc3e --format xml,elastic,evtx,auditd  # All formats
./artiforge.sh generate --lab uc3e --seed 42               # Deterministic output
./artiforge.sh generate --lab uc3e --jitter 5              # Timestamp jitter
./artiforge.sh generate --lab uc3e --no-meta               # Strip training metadata
./artiforge.sh generate --lab uc3e --phases 1,4            # Specific phases only
./artiforge.sh generate --lab uc3e --dry-run               # Preview, no files

./artiforge.sh check --lab uc3e --sigma-only               # Sigma rules only
./artiforge.sh check --lab uc3e --sigma-dir ./my_rules/    # External Sigma rules
```

---

## Output

```
artifacts/uc3e_20260219_091200/
├── events/                          Windows Event XML
│   ├── WIN-WS1_Security.xml
│   ├── WIN-WS1_Sysmon.xml
│   └── ...
├── elastic/
│   └── bulk_import.ndjson           Elasticsearch NDJSON (ECS-mapped)
├── evtx/                            Binary EVTX
│   ├── WIN-WS1_Security.evtx
│   ├── WIN-WS1_Sysmon.evtx
│   └── ...
├── forensics/                       Filesystem artifacts
│   ├── WIN-WS1/
│   │   ├── prefetch/
│   │   │   ├── IE4UINIT.EXE-95870A03.pf
│   │   │   ├── MIMIKATZ.EXE-A1B2C3D4.pf
│   │   │   └── ...
│   │   ├── amcache_entries.json
│   │   └── mft_entries.json
│   └── WIN-WS2/
│       └── ...
├── files/                           Attack file artifacts
│   ├── phase01/                     LNK lure, XSL, INF
│   ├── phase02/                     Scheduled task XML
│   └── phase04/                     Cloudflared binary stub
├── navigator_layer.json             MITRE ATT&CK Navigator
└── IMPORT.md                        Import instructions
```

---

## Labs

| ID | Name | Events | Noise | Forensics | Sigma |
|----|------|--------|-------|-----------|-------|
| `uc3` | Egg-Cellent Resume | 40 | — | — | 3 rules |
| `uc3n` | Egg-Cellent Resume (Noisy) | 40 + ~143 noise | Manual counts | — | — |
| `uc3e` | Egg-Cellent Resume (Enhanced) | 44 + ~234 noise | `office_hours` / `24x7_server` profiles | Prefetch + Amcache + $MFT | 5 rules |

All labs use the same LOLBAS + Cloudflared + Veeam CVE-2023-27532 attack chain across 5 phases. UC3E showcases all v0.7-v1.0 features.

---

## Event Coverage — 71 EIDs

| Channel | Count | EIDs |
|---------|-------|------|
| Security | 30 | 1102 4624 4625 4634 4648 4656 4657 4663 4670 4672 4688 4697 4698 4703 4719 4720 4723 4724 4725 4726 4732 4735 4768 4769 4771 4776 4946 4947 5156 5157 |
| Sysmon | 20 | 1 3 5 6 7 8 10 11 12 13 14 15 16 17 18 22 23 24 25 26 |
| System | 4 | 7031 7034 7036 7045 |
| PowerShell | 6 | 4103 4104 4105 4106 40961 40962 |
| WMI | 3 | 5857 5860 5861 |
| Application | 1 | 1 |
| Auditd (Linux) | 7 | SYSCALL EXECVE PATH SOCKADDR USER_AUTH USER_LOGIN CRED_ACQ |

---

## Export Formats

| Format | Flag | Tool Compatibility |
|--------|------|--------------------|
| Windows XML | `--format xml` | Windows Event Viewer, wevtutil |
| Elasticsearch NDJSON | `--format elastic` | Kibana, Elastic SIEM (ECS-mapped) |
| Binary EVTX | `--format evtx` | Chainsaw, Hayabusa, Get-WinEvent, Event Viewer |
| Raw audit.log | `--format auditd` | ausearch, aureport, grep |
| Forensic artifacts | `forensic_artifacts: true` in YAML | PECmd (Prefetch), AmcacheParser, MFTECmd |

---

## Noise Profiles

Labs can specify a `noise_profile` to generate realistic background activity:

```yaml
noise:
  - host: WIN-WS1
    noise_profile: office_hours    # events cluster 08:00-18:00
    process_spawns: 30             # override default count
```

| Profile | Pattern |
|---------|---------|
| `office_hours` | Morning ramp-up, lunch dip, afternoon peak, quiet nights |
| `24x7_server` | Steady with slight overnight dip |
| `developer_workstation` | Deep focus AM, lunch gap, PM burst, occasional late night |

8 noise types: logon pairs, process spawns, DNS queries, file operations, registry writes, service changes, network connections, Windows Update (correlated 3-event burst).

---

## Detection Rules

### Built-in (13 rules)

```bash
artiforge check --lab uc3e --seed 42
```

### Sigma (custom rules)

Labs can bundle Sigma YAML rules in a `sigma/` subdirectory — auto-discovered by `artiforge check`:

```bash
artiforge check --lab uc3e                    # built-in + bundled Sigma
artiforge check --lab uc3e --sigma-only       # Sigma only
artiforge check --lab uc3e --sigma-dir ./rules/  # external rules
```

Supported Sigma syntax: selections, modifiers (`|contains`, `|startswith`, `|endswith`, `|all`), wildcards, list OR, conditions (`and`, `or`, `not`, `1 of`, `all of`).

---

## Creating a New Lab

```bash
artiforge new-lab --id uc4-kerberoast --name "Kerberoasting Lab" --output .
# Edit lab.yaml — see docs/LAB_AUTHORING_GUIDE.md
artiforge validate --lab-path ./uc4-kerberoast/lab.yaml --strict
artiforge generate --lab-path ./uc4-kerberoast/lab.yaml
```

Labs support mixed Windows + Linux hosts:

```yaml
infrastructure:
  hosts:
    WIN-WS1:
      platform: windows
      os: "Windows 10 22H2"
    LNX-WEB1:
      platform: linux
      os: "Ubuntu 22.04 LTS"
```

Full authoring reference: **[docs/LAB_AUTHORING_GUIDE.md](docs/LAB_AUTHORING_GUIDE.md)**

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for details and [CHANGELOG.md](CHANGELOG.md) for version history.

| Milestone | Focus | Status |
|-----------|-------|--------|
| **v0.1–v0.6** | Foundation, event coverage, noise, tooling, web UI, Kibana realism | Done |
| **v0.7** | Event correlation engine, 16 new EIDs, validation | Done |
| **v0.8** | Binary EVTX export (evtxforge), Sigma rule evaluator | Done |
| **v0.9** | Noise Engine v2, Linux auditd channel | Done |
| **v1.0** | Filesystem artifacts (Prefetch, Amcache, $MFT) | Done |

---

## Contributing

Bug reports, new EID generators, and new lab scenarios are all welcome.
See [CLAUDE.md](CLAUDE.md) for the developer guide and architecture overview.

---

## License

[MIT](LICENSE) — Built by [D3vn0mi](https://github.com/D3vn0mi)
