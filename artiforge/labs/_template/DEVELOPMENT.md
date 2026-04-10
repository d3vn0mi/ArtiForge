# Lab Development Quick Start

For the full guide — field reference, event patterns, timing model, and
troubleshooting — see **[docs/LAB_AUTHORING_GUIDE.md](../../../docs/LAB_AUTHORING_GUIDE.md)**.

---

## Workflow

```bash
# 1. Edit lab.yaml — replace every line marked FIXME
code lab.yaml

# 2. Validate schema (catches errors early)
artiforge validate --lab-path ./lab.yaml

# 3. Validate with realism checks
artiforge validate --lab-path ./lab.yaml --strict

# 4. Preview output without writing files
artiforge generate --lab-path ./lab.yaml --dry-run

# 5. Generate artifacts
artiforge generate --lab-path ./lab.yaml

# 6. Check detection rule coverage
artiforge check --lab-path ./lab.yaml
```

## File Structure

After editing `lab.yaml` and running `generate`:

```
my-lab/
├── lab.yaml              <- Main lab specification (edit this)
└── DEVELOPMENT.md        <- This file

artifacts/
└── my-lab_20260219_091200/
    ├── events/            <- Windows XML event logs (one per host+channel)
    ├── elastic/
    │   └── bulk_import.ndjson
    ├── files/             <- Staged file artifacts
    ├── navigator_layer.json
    └── IMPORT.md
```

## lab.yaml Structure

```yaml
lab:              # Metadata: id, name, description, MITRE version
infrastructure:   # Hosts, IPs, SIDs, users
attack:           # Base time, phases, events, noise
```

## Supported Channels and EIDs

| Channel | EIDs |
|---------|------|
| Security | 4624, 4625, 4634, 4648, 4656, 4657, 4663, 4670, 4672, 4688, 4698, 4720, 4723, 4724, 4725, 4726, 4732, 4768, 4769, 4771, 4776, 4946, 4947, 5156, 5157 |
| System | 7036, 7045 |
| Sysmon | 1, 3, 5, 7, 8, 10, 11, 12, 13, 14, 17, 18, 22, 23, 25 |
| Application | 1 |
| PowerShell | 4103, 4104 |
| WMI | 5857, 5860, 5861 |

## Key Conventions

- **Always pair Security 4688 with Sysmon 1** for process creation (same `offset_seconds`)
- **Use YAML anchors** (`&name` / `*name`) to share `ProcessGuid` between Sysmon events from the same process
- **Quote numeric strings** — `LogonType: '10'` not `LogonType: 10`
- **Use `%%` prefix** — `TokenElevationType: '%%1938'`
- **Override host/user per-event** for cross-host activity (e.g., RDP lateral movement)
- **Noise events** are tagged `phase_id=0` and excluded from detection scoring

## Useful Generate Options

```bash
artiforge generate --lab-path ./lab.yaml --seed 42        # Deterministic output
artiforge generate --lab-path ./lab.yaml --jitter 5       # +/-5s timestamp jitter
artiforge generate --lab-path ./lab.yaml --phases 1,2     # Specific phases only
artiforge generate --lab-path ./lab.yaml --format xml     # XML only
```
