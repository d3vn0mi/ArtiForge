# ArtiForge Roadmap

> Maintained by [D3vn0mi](https://github.com/D3vn0mi)

This document tracks planned improvements across five dimensions:
event coverage, realism, lab ecosystem, MITRE integration, and distribution.
Items within each milestone are roughly ordered by priority.

---

## v0.1 — Foundation ✓

- [x] YAML-driven lab specification with Pydantic v2 validation
- [x] Security channel: 4624, 4625, 4634, 4648, 4672, 4688, 4698, 4720, 4732, 4776
- [x] System channel: 7036, 7045
- [x] Sysmon channel: 1, 3, 11, 13, 22
- [x] Application channel: EID 1
- [x] PowerShell channel: 4103, 4104
- [x] XML export (Windows Event Viewer compatible)
- [x] Elasticsearch NDJSON bulk export (ECS-mapped)
- [x] File artifact generation: lnk, xsl, inf, xml_task, binary_placeholder, raw
- [x] CLI: generate, validate, schema, list-labs, info, new-lab
- [x] `--dry-run`, `--lab-path`, `--phases`, `--base-time` flags
- [x] JSON Schema for VS Code YAML autocompletion
- [x] Docker support: Dockerfile + wrapper script
- [x] Lab template + DEVELOPMENT.md for new scenario authors
- [x] UC3 "Egg-Cellent Resume" scenario (LOLBAS + Cloudflared + Veeam pivot)

---

## v0.2 — Event Coverage Expansion ✓

The core generator layer needs a wider net before more scenarios can be built.

### Authentication & Account Events (Security)
- [x] **4768** — Kerberos TGT requested (AS-REQ)
- [x] **4769** — Kerberos service ticket requested (TGS-REQ)
- [x] **4771** — Kerberos pre-authentication failed (bad password at DC)
- [x] **4723/4724** — Password change / password reset by admin
- [x] **4725/4726** — Account disabled / account deleted

### Object & Registry Access (Security)
- [x] **4656** — A handle to an object was requested
- [x] **4663** — An attempt was made to access an object (file read/write/delete)
- [x] **4657** — A registry value was modified
- [x] **4670** — Permissions on an object were changed

### Network Policy & Firewall (Security / System)
- [x] **5156** — Windows Filtering Platform connection allowed
- [x] **5157** — Windows Filtering Platform connection blocked
- [x] **4946/4947** — Windows Firewall rule added / modified

### Sysmon
- [x] **5** — Process terminated (pairs with EID 1 for full lifecycle)
- [x] **7** — Image loaded (DLL side-loading / reflective injection detection)
- [x] **8** — CreateRemoteThread (process injection)
- [x] **10** — ProcessAccess (credential dumping via LSASS access)
- [x] **12/14** — RegistryEvent: key/value create+delete / key renamed
- [x] **17/18** — PipeEvent: pipe created / pipe connected (lateral movement)
- [x] **23** — FileDelete (evidence tampering)
- [x] **25** — ProcessTampering (process hollowing/herpaderping)

### WMI Events (Microsoft-Windows-WMI-Activity/Operational)
- [x] **5857/5860/5861** — WMI activity: provider loaded, subscription created, filter/consumer bound

---

## v0.3 — Realism & Noise ✓

Real environments are noisy. Artifacts generated in total silence are easy to detect
as synthetic. This milestone adds controllable realism layers.

### Background Noise
- [x] `noise:` section in lab YAML — inject configurable volumes of benign events
  (user logons, process creation, DNS queries) that trainees must filter out
- [x] Common process allowlist (chrome.exe, svchost.exe, RuntimeBroker.exe, etc.)
  with realistic parent/child chains
- [x] Randomised logon/logoff pairs (Security 4624 + 4634) throughout the timeline

### Field Variation
- [x] `--seed` flag for deterministic but varied field values (PIDs, GUIDs, ports)
  so each generation run looks different while remaining reproducible
- [x] `--jitter N` global timestamp jitter: each event is shifted ±N seconds
- [x] Per-event `jitter_seconds` field in YAML for fine-grained control
- [x] GUIDs generated via seeded RNG (fully deterministic under `--seed`)

### Beaconing Pattern
- [x] `repeat_jitter_seconds` on EventSpec: adds ±N second variation to each
  inter-beacon interval for more realistic C2 timing patterns

---

## v0.4 — Lab Quality & Tooling ✓

Better guardrails for scenario authors.

- [x] `artiforge check` — run 13 built-in detection rules against a generated bundle
  and report which ones fire (coverage %)
- [x] `artiforge diff --lab A --other B` — compare two generated bundles: total events,
  attack vs noise split, per-phase and per-EID deltas
- [x] `artiforge graph --lab X` — phase dependency graph showing ProcessGuid and
  LogonId correlation chains across attack events
- [x] `artiforge validate --strict` — warns on placeholder hashes, offset monotonicity
  violations, and process creation before any logon on the same host
- [x] Schema versioning: `lab_schema_version: "1"` field in LabMeta; engine emits
  a `UserWarning` when a lab's version does not match the current engine version

---

## v0.5 — MITRE ATT&CK Integration & Web UI (current)

### MITRE ATT&CK Integration
- [ ] Navigator layer JSON export for each lab (techniques highlighted per phase)
- [ ] Inline technique IDs in generated event descriptions
- [ ] Coverage matrix: which techniques each built-in lab exercises

### Web UI (optional, Docker only)
- [ ] Browser-based lab browser + one-click generation
- [ ] Timeline visualisation rendered from the bundle without Kibana
- [ ] Trainer dashboard: show expected detections alongside generated events

---

## v0.6 — Kibana Realism

- [ ] Rename `artiforge.*` → `labels.*` in NDJSON export (ECS-standard namespace;
  `labels.*` appears in real Winlogbeat data so raw `_source` looks authentic)
  — changes: `exporters/elastic.py`, `scripts/setup_index.sh`, `tests/test_exporters.py`,
  `QUICKSTART.md`, `labs/uc3n/trainee_brief.md`, `labs/uc3/trainer_guide.md`
- [ ] `--no-meta` flag on `generate` — strips the `labels` block entirely from NDJSON
  for max-realism scenarios where phase grading is done out-of-band
  — changes: `exporters/elastic.py` (`include_meta=True` default), `cli.py`

---

## v0.9 — Distribution

- [ ] PyPI package (`pip install artiforge`)
- [ ] GitHub Actions CI: test matrix across Python 3.10/3.11/3.12
- [ ] Pre-built Docker image on GitHub Container Registry (`ghcr.io/d3vn0mi/artiforge`)
- [ ] Signed releases with checksums

---

## v1.0 — Scenario Library

A standalone tool is useful; a curated library is a training platform.

- [ ] UC4 — Kerberoasting + Pass-the-Hash lateral movement
- [ ] UC5 — Supply chain: malicious npm package → C2 beacon
- [ ] UC6 — Ransomware: file encryption + shadow copy deletion
- [ ] UC7 — Insider threat: data staging + USB exfiltration
- [ ] UC8 — Living-off-the-land: wmic/mshta/regsvr32 chains
- [ ] UC9 — Cloud pivot: IMDS credential theft + lateral to S3
- [ ] UC10 — Active Directory: DCSync + Golden Ticket

---

## Contributing

Bug reports, new EID generators, and new lab scenarios are all welcome.
See `artiforge/labs/_template/DEVELOPMENT.md` for the lab authoring guide
and `artiforge/generators/security.py` for the generator pattern.
