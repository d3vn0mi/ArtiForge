# ArtiForge Roadmap

> Maintained by [D3vn0mi](https://github.com/D3vn0mi)

This document tracks planned improvements across seven dimensions:
event coverage, event correlation, realism, export formats, cross-platform
support, lab ecosystem, and distribution.
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

## v0.5 — MITRE ATT&CK Integration & Web UI ✓

### MITRE ATT&CK Integration
- [x] Navigator layer JSON export for each lab (techniques highlighted per phase)
  — `artiforge navigator --lab uc3` and auto-written by `artiforge generate`
- [x] Inline technique IDs in generated events — `mitre_techniques` field on
  `GeneratedEvent`; emitted as ECS `threat.technique.id/name` in Elasticsearch
- [x] Coverage matrix — `artiforge coverage` prints a techniques × labs table

### Web UI (optional, Docker only)
- [x] Browser-based lab browser — `artiforge serve` (requires `pip install artiforge[web]`)
- [x] Timeline visualisation rendered from the bundle without Kibana
  — colour-coded by phase, noise toggle, per-phase filter, MITRE badges
- [x] Trainer dashboard — detection rule results (fired/not, match counts,
  coverage %) and phase summary alongside the generated event timeline

---

## v0.6 — Kibana Realism ✓

- [x] Rename `artiforge.*` → `labels.*` in NDJSON export (ECS-standard namespace;
  `labels.*` appears in real Winlogbeat data so raw `_source` looks authentic)
- [x] `--no-meta` flag on `generate` — strips the `labels` block entirely from NDJSON
  for max-realism scenarios where phase grading is done out-of-band

---

## v0.7 — Event Correlation & Coverage Expansion ✓

### Event Correlation Engine
- [x] `CorrelationContext` per (phase, host) — tracks `LogonId`, `LogonGuid`,
  `ProcessGuid`, and `TargetLogonId` across related events
- [x] Three-tier field precedence: YAML fields > correlation > random default
- [x] `session` and `process` labels on EventSpec for multi-session scenarios
- [x] Realistic PID ranges (multiples of 4, categorized by process type)

### Expanded Event Coverage
- [x] **Security:** 1102, 4697, 4703, 4719, 4735 (5 new EIDs)
- [x] **Sysmon:** 6, 15, 16, 24, 26 (5 new EIDs)
- [x] **System:** 7031, 7034 (2 new EIDs)
- [x] **PowerShell:** 4105, 4106, 40961, 40962 (4 new EIDs)

### Event Sequence Validation
- [x] Correlation-aware `--strict` checks: ProcessGuid matching, orphan logoff
  detection, session-before-activity

---

## v0.8 — Export Formats & Detection Standards ✓

### Binary EVTX Export (evtxforge)
- [x] Pure-Python `evtxforge` library (`libs/evtxforge/`) — zero dependencies
- [x] `--format evtx` producing valid `.evtx` files (file header, chunks,
  BinXML event records, CRC32 checksums)
- [x] One `.evtx` file per host/channel pair

### Lightweight Sigma Rule Evaluator
- [x] Custom Sigma YAML evaluator — no pySigma dependency, ~80% syntax coverage
- [x] Supports selections, modifiers (contains/startswith/endswith/all),
  wildcards, conditions (and/or/not, 1 of, all of)
- [x] `artiforge check --sigma-dir ./rules/ --sigma-only`
- [x] Auto-discovery of `sigma/` directory in lab folders
- [x] 3 starter Sigma rules shipped with UC3

---

## v0.9 — Realism & Cross-Platform ✓

### Realistic Noise Engine v2
- [x] 5 new noise categories: file operations (Sysmon 11), registry writes
  (Sysmon 13), service start/stop (System 7036), network connections
  (Sysmon 3), Windows Update traffic (correlated DNS + HTTP + file burst)
- [x] 3 temporal profiles: `office_hours`, `24x7_server`,
  `developer_workstation` with hour-weighted distribution curves
- [x] `noise_profile` preset system with per-field overrides

### Linux Auditd Channel
- [x] `platform` field on Host (`"windows"` | `"linux"`, backward-compatible)
- [x] 7 auditd record type generators: SYSCALL, EXECVE, PATH, SOCKADDR,
  USER_AUTH, USER_LOGIN, CRED_ACQ
- [x] String EID aliases in lab YAML (`eid: USER_AUTH`)
- [x] Raw `audit.log` exporter (`--format auditd`)
- [x] ECS-mapped NDJSON output matching Auditbeat schema
- [x] Mixed Windows + Linux hosts in the same lab

---

## v1.0 — Filesystem Artifact Generation

Cross-artifact correlation: event logs tell one story, filesystem artifacts
confirm it. Trainees learn to corroborate findings across evidence sources.

### Filesystem Artifact Generation
- [ ] Prefetch files (`.pf`) with execution counts, timestamps, and referenced
  DLLs — correlated with Sysmon 1 process creation events
- [ ] Amcache registry hive entries for executed binaries
- [ ] $MFT stub records (filename, timestamps, parent directory) for key
  attack-path files
- [ ] Cross-artifact correlation: if Sysmon 1 says `mimikatz.exe` ran, the
  Prefetch and Amcache entries confirm it

---

## Backlog

Items deferred from earlier milestones. Will be prioritized as needed.

- [ ] **Multi-Timezone & Locale** — per-host timezone field, local time
  rendering in exports (deferred from v0.9 — low value without multi-region labs)
- [ ] **Splunk CIM / HEC Export** — `--format splunk` with CIM field mapping
  (deferred from v0.8 — Elastic covers most cohorts)
- [ ] **Noise correlation via CorrelationContext** — noise events currently use
  independent GUIDs/PIDs (deferred from v0.7)
- [ ] **Cross-phase correlation** — `continues_session` directive to carry
  session state across phases (deferred from v0.7)
- [ ] **Template-based BinXML** in evtxforge — for python-evtx readback
  compatibility (current inline BinXML works with Chainsaw/Hayabusa)
- [ ] **Scenario Library** — UC4 (Kerberoasting), UC5 (Supply Chain),
  UC6 (Ransomware), UC7 (Insider Threat), UC8 (LOLBins), UC9 (Cloud Pivot),
  UC10 (AD: DCSync + Golden Ticket)
- [ ] **Distribution** — PyPI package, GitHub Actions CI, pre-built Docker
  image on GHCR, signed releases

---

## Contributing

Bug reports, new EID generators, and new lab scenarios are all welcome.
See `artiforge/labs/_template/DEVELOPMENT.md` for the lab authoring guide
and `artiforge/generators/security.py` for the generator pattern.
