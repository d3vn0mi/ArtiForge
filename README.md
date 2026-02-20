# ArtiForge

> YAML-driven Windows event artifact generator for cybersecurity training labs.

ArtiForge generates realistic Windows event logs (Security, System, Sysmon, Application)
and supporting file stubs from a declarative YAML lab specification. Output can be
imported directly into Elasticsearch or opened in Windows Event Viewer.

---

## Quick Start

```bash
pip install -e .

# List available labs
artiforge list-labs

# Generate all UC3 artifacts (XML + Elastic NDJSON)
artiforge generate --lab uc3

# Selective phases only
artiforge generate --lab uc3 --phases 1,4 --output ./test_out

# Custom base timestamp
artiforge generate --lab uc3 --base-time "2026-03-01T08:00:00Z"
```

---

## Output Structure

```
artifacts/
└── uc3_20260219_091200/
    ├── events/
    │   ├── WIN-WS1_Security.xml     # importable via Windows Event Viewer
    │   ├── WIN-WS1_Sysmon.xml
    │   ├── WIN-WS1_System.xml
    │   ├── WIN-WS1_Application.xml
    │   ├── WIN-BACKUP1_Security.xml
    │   ├── WIN-WS2_Security.xml
    │   └── WIN-WS2_Sysmon.xml
    ├── elastic/
    │   └── bulk_import.ndjson       # Elasticsearch bulk API format
    ├── files/
    │   ├── phase01/                 # LNK lure, XSL stylesheet, INF file
    │   ├── phase02/                 # XML task definition (.txt extension)
    │   └── phase04/                 # cloudflared placeholder README
    └── IMPORT.md                    # step-by-step import instructions
```

---

## Labs

| ID  | Name | Phases | Description |
|-----|------|--------|-------------|
| uc3 | Egg-Cellent Resume | 5 | LOLBAS + Cloudflared + Veeam Pivot |

---

## Adding a New Lab

1. Create `artiforge/labs/<your-lab-id>/lab.yaml`
2. Follow the schema from `artiforge/labs/uc3/lab.yaml`
3. Run `artiforge list-labs` — your lab appears automatically

No Python code changes required for YAML-only labs.

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
