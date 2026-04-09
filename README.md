# ArtiForge

> YAML-driven Windows event artifact generator for cybersecurity training labs.
> Built by [D3vn0mi](https://github.com/D3vn0mi) · v0.1 · [MIT License](LICENSE) · [Roadmap](ROADMAP.md)

ArtiForge generates realistic Windows event logs (Security, System, Sysmon, PowerShell, Application)
and supporting file stubs from a declarative YAML lab specification. Output can be
imported directly into Elasticsearch/Kibana or opened in Windows Event Viewer.

---

## Quick Start

### Python (local install)

```bash
pip install -e .

artiforge list-labs
artiforge generate --lab uc3
artiforge generate --lab uc3 --dry-run
```

### Docker (no Python required)

```bash
# Build once
docker build -t artiforge:latest .

# Run any command — output lands in ./artifacts/ on your host
./artiforge.sh list-labs
./artiforge.sh generate --lab uc3
./artiforge.sh generate --lab uc3 --dry-run
```

The wrapper script (`artiforge.sh`) mounts your current directory into the
container and forwards all arguments. Generated artifacts are written directly
to `./artifacts/` on your host, owned by your user.

---

## All Commands

```bash
# List available labs
artiforge list-labs

# Detailed lab info
artiforge info --lab uc3

# Generate all UC3 artifacts (XML + Elastic NDJSON)
artiforge generate --lab uc3

# Preview what would be generated (no files written)
artiforge generate --lab uc3 --dry-run

# Selective phases
artiforge generate --lab uc3 --phases 1,4 --output ./test_out

# Custom base timestamp
artiforge generate --lab uc3 --base-time "2026-03-01T08:00:00Z"

# Use a lab YAML from anywhere on disk
artiforge generate --lab-path /home/analyst/mylab/lab.yaml

# Validate before generating (schema + EID coverage check)
artiforge validate --lab uc3
artiforge validate --lab-path /home/analyst/mylab/lab.yaml

# Scaffold a new lab from the built-in template
artiforge new-lab --id my-scenario --name "My Attack Scenario" --output ~/mylabs

# Print or save the JSON Schema for IDE autocompletion
artiforge schema
artiforge schema --output artiforge/labs/lab.schema.json
```

---

## Output Structure

```
artifacts/
└── uc3_20260219_091200/
    ├── events/
    │   ├── WIN-WS1_Security.xml      # importable via Windows Event Viewer
    │   ├── WIN-WS1_Sysmon.xml
    │   ├── WIN-WS1_System.xml
    │   ├── WIN-WS1_Application.xml
    │   ├── WIN-BACKUP1_Security.xml
    │   ├── WIN-WS2_Security.xml
    │   └── WIN-WS2_Sysmon.xml
    ├── elastic/
    │   └── bulk_import.ndjson        # Elasticsearch bulk API format
    ├── files/
    │   ├── phase01/                  # LNK lure, XSL stylesheet, INF file
    │   ├── phase02/                  # XML task definition
    │   └── phase04/                  # cloudflared placeholder
    └── IMPORT.md                     # step-by-step import instructions
```

---

## Labs

| ID  | Name | Phases | Description |
|-----|------|--------|-------------|
| uc3 | Egg-Cellent Resume | 5 | LOLBAS + Cloudflared + Veeam CVE-2023-27532 pivot |

See [ROADMAP.md](ROADMAP.md) for the planned lab library (UC4–UC10).

---

## Adding a New Lab

```bash
# 1. Scaffold from the built-in template
artiforge new-lab --id uc4-kerberoast --name "Kerberoasting Lab" --output ~/mylabs

# 2. Fill in every FIXME in the generated lab.yaml
#    (see artiforge/labs/_template/DEVELOPMENT.md for the full authoring guide)

# 3. Validate
artiforge validate --lab-path ~/mylabs/uc4-kerberoast/lab.yaml

# 4. Generate
artiforge generate --lab-path ~/mylabs/uc4-kerberoast/lab.yaml
```

**VS Code autocompletion:** install the Red Hat YAML extension and the
`.vscode/settings.json` in this repo wires the JSON Schema automatically —
every field autocompletes with inline documentation.

**No Python code changes required** as long as your scenario uses the supported EIDs.
To add a new EID, add a generator function following the pattern in
`artiforge/generators/security.py` (see [ROADMAP.md](ROADMAP.md) — v0.2 coverage expansion).

### Supported EIDs

| Channel | EIDs |
|---------|------|
| Security | 4624, 4625, 4634, 4648, 4672, 4688, 4698, 4720, 4732, 4776 |
| System | 7036, 7045 |
| Sysmon | 1, 3, 11, 13, 22 |
| Application | 1 |
| PowerShell | 4103, 4104 |

---

## Event Coverage (UC3)

| Phase | Events Generated |
|-------|-----------------|
| 01 – Initial Access | Sysmon 11 (file drops), 4688 + Sysmon 1 (ie4uinit → msxsl → cmd chain) |
| 02 – Persistence | Sysmon 11 (task XML drop), 4688 + Sysmon 1 (schtasks /XML), 4698 (task created), Sysmon 13 (registry) |
| 03 – Veeam Pivot | Sysmon 3 (TCP 9401), 4688 + Sysmon 1 (wmic recon), 4720 + 4732 (account created/added), 4648 (explicit creds) |
| 04 – Cloudflared | Sysmon 11 (binary drop), 4688 + Sysmon 1 (sc create/start), 7045 (service install), Sysmon 3 x5 (failed egress), App 1 (error) |
| 05 – Lateral Movement | 4648 (explicit creds RDP), 4624 Type 10 (RDP logon), 4688 + Sysmon 1 (Compress-Archive), Sysmon 11 (ZIP created), 4634 (logoff) |

---

## MITRE ATT&CK Coverage

T1204.002 · T1566.001 · T1218 · T1218.010 · T1053.005 · T1210 · T1136.001 · T1078 ·
T1572 · T1543.003 · T1036.004 · T1021.001 · T1550.002 · T1560.001

---

## License

MIT — see [LICENSE](LICENSE). Built by [D3vn0mi](https://github.com/D3vn0mi).
