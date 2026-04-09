# ArtiForge Roadmap

> Maintained by [D3vn0mi](https://github.com/D3vn0mi)

This document tracks planned improvements across four dimensions:
event coverage, realism, lab ecosystem, and export integrations.
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

## v0.2 — Event Coverage Expansion ✓ (current)

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

## v0.3 — Realism & Noise ✓ (current)

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

## v0.4 — Lab Quality & Tooling

Better guardrails for scenario authors.

- [ ] `artiforge check` — run all known detection rules against a generated bundle
  and report which ones fire (confidence that the scenario is detectable)
- [ ] Lab diff: compare two generated bundles to show what changed between
  lab YAML edits
- [ ] Phase dependency graph — visualise which events depend on which via
  ProcessGuid / LogonId / correlation fields
- [ ] `artiforge validate --strict` — warn on common realism mistakes:
  missing logon before process creation, impossible parent/child combos,
  placeholder hashes still in place, etc.
- [ ] Schema versioning: `lab_schema_version: "1"` field so the engine
  can migrate older lab YAML files forward automatically

---

## v1.0 — Lab Ecosystem

A standalone tool is useful; a curated library is a training platform.

### Scenario Library (10+ built-in labs)
- [ ] UC4 — Kerberoasting + Pass-the-Hash lateral movement
- [ ] UC5 — Supply chain: malicious npm package → C2 beacon
- [ ] UC6 — Ransomware: file encryption + shadow copy deletion
- [ ] UC7 — Insider threat: data staging + USB exfiltration
- [ ] UC8 — Living-off-the-land: wmic/mshta/regsvr32 chains
- [ ] UC9 — Cloud pivot: IMDS credential theft + lateral to S3
- [ ] UC10 — Active Directory: DCSync + Golden Ticket

### MITRE ATT&CK Integration
- [ ] Navigator layer JSON export for each lab (techniques highlighted per phase)
- [ ] Inline technique IDs in generated event descriptions
- [ ] Coverage matrix: which techniques each built-in lab exercises

### Web UI (optional, Docker only)
- [ ] Browser-based lab browser + one-click generation
- [ ] Timeline visualisation rendered from the bundle without Kibana
- [ ] Trainer dashboard: show expected detections alongside generated events

### Distribution
- [ ] PyPI package (`pip install artiforge`)
- [ ] GitHub Actions CI: test matrix across Python 3.10/3.11/3.12
- [ ] Pre-built Docker image on GitHub Container Registry (`ghcr.io/d3vn0mi/artiforge`)
- [ ] Signed releases with checksums

---

## v1.1 — Export & Integration

Make artifacts importable into more SIEM/EDR platforms without manual transformation.

### New Export Formats
- [ ] **Splunk HEC** — JSON payload for the HTTP Event Collector (`/services/collector/event`)
- [ ] **Microsoft Sentinel** — Log Analytics workspace JSON (`LogManagementAPI` table format)
- [ ] **QRadar LEEF** — Log Event Extended Format for IBM QRadar
- [ ] **CEF** — Common Event Format (ArcSight, generic syslog destinations)

### Elastic Improvements
- [ ] Detection rule NDJSON export (EQL/KQL stubs with MITRE metadata)
- [ ] Index template + ILM policy auto-creation on first import
- [ ] Kibana saved search + dashboard NDJSON alongside the bulk import

### Reporting
- [ ] HTML timeline report — chronological event table with phase colour-coding,
  rendered from the bundle without requiring Kibana

---

## Contributing

Bug reports, new EID generators, and new lab scenarios are all welcome.
See `artiforge/labs/_template/DEVELOPMENT.md` for the lab authoring guide
and `artiforge/generators/security.py` for the generator pattern.
