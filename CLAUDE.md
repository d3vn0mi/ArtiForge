# ArtiForge — Developer Guide

YAML-driven Windows + Linux event artifact generator for cybersecurity
training labs. Generates forensically-sound event logs, filesystem artifacts,
and detection rules from declarative lab specifications.

## Quick Start

```bash
# Install (editable, with evtxforge)
pip install -e libs/evtxforge && pip install -e ".[web]"

# Run tests
python3 -m pytest tests/ -q

# Generate artifacts
artiforge generate --lab uc3e --format xml,elastic,evtx --seed 42

# Run detection check
artiforge check --lab uc3e --seed 42

# Start web dashboard
artiforge serve --port 5000
```

## Architecture

```
artiforge/
├── core/           Engine, models, correlation context, timeline
├── generators/     Event generators (security, sysmon, system, powershell,
│                   wmi, application, linux_auditd, noise, forensic artifacts)
├── exporters/      XML, NDJSON (ECS), EVTX, audit.log
├── detectors/      13 built-in rules + Sigma evaluator
├── mitre/          ATT&CK v18 technique names + navigator layers
├── web/            Flask dashboard (templates in web/templates/)
├── labs/           Lab specifications (uc3, uc3n, uc3e, _template)
└── cli.py          Click CLI — all commands

libs/evtxforge/     Standalone EVTX binary writer (separate package)
```

## Key Patterns

### Adding a new Event ID

1. Add the generator function to the appropriate module in `generators/`
   (e.g., `security.py` for Security channel EIDs)
2. Follow the existing pattern: `def eid_XXXX(fields, host, user, ctx=None,
   session_label="default", **_) -> dict:`
3. Register it in the module's `_GENERATORS` dict
4. Add a test in `tests/test_generators.py` or a dedicated test file
5. If the EID consumes correlation context, use `_resolve()` for
   `SubjectLogonId` or `_resolve_process()` for `ProcessGuid/ProcessId`

### Adding a new export format

1. Create `artiforge/exporters/<format>_exporter.py`
2. Implement `export(bundle: ArtifactBundle, output_dir: Path) -> list[Path]`
3. Add the format to `cli.py`'s `generate` command (after the EVTX block)
4. Update the `--format` help text

### Adding a new lab

1. Copy `artiforge/labs/_template/` to `artiforge/labs/<lab_id>/`
2. Edit `lab.yaml` following the schema (`artiforge schema` for reference)
3. Optionally add `sigma/` directory with detection rules
4. Validate: `artiforge validate --lab <lab_id> --strict`
5. See `docs/LAB_AUTHORING_GUIDE.md` for full details

## Testing

```bash
# Full suite
python3 -m pytest tests/ -q

# Specific module
python3 -m pytest tests/test_correlation.py -v

# evtxforge tests (separate package)
PYTHONPATH=libs/evtxforge python3 -m pytest libs/evtxforge/tests/ -v
```

Tests use `pytest`. Fixtures provide common `host`, `user`, `ts`, `spec_stub`
objects. Generator tests follow TDD — test the output dict for required
fields and correct values.

## Conventions

- **Python 3.10+** — uses `X | Y` union syntax, not `Optional[X]`
- **Pydantic v2** for all models
- **Click** for CLI
- **No external deps** in generators/exporters (stdlib only)
- **Event data is always `dict[str, str]`** — all values are strings
- **Noise events** have `phase_id=0`, `phase_name="noise"`
- **Correlation context** resets per phase boundary
- **`--seed` determinism** — same seed must produce identical output

## Common Commands

```bash
artiforge list-labs                          # Show available labs
artiforge info --lab uc3                     # Lab details
artiforge generate --lab uc3e --format evtx  # Generate EVTX
artiforge validate --lab uc3 --strict        # Validate with realism checks
artiforge check --lab uc3e --sigma-only      # Sigma rules only
artiforge diff --lab uc3 --other uc3n        # Compare two labs
artiforge coverage                           # MITRE technique coverage matrix
artiforge schema                             # Print JSON Schema
```
