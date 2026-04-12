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

## v0.7 — Event Correlation & Coverage Expansion

Foundational realism: events that reference each other correctly, more
detectable behaviours, and guardrails that prevent impossible timelines.

### Event Correlation Engine
- [ ] Correlation context per phase — tracks `LogonId`, `LogonGuid`,
  `ProcessGuid`, and `TargetLogonId` across related events on the same host
- [ ] Related events automatically share correct identifiers (e.g. Sysmon 1 +
  Sysmon 5 for the same process carry the same `ProcessGuid`; 4624 logon and
  subsequent 4688 process creations share `LogonId`)
- [ ] Cross-event GUID/ID registry exposed to lab authors for explicit
  correlation overrides

### Expanded Event Coverage — Existing Channels
- [ ] **Security:** 4697 (service install), 4703 (token privilege adjusted),
  1102 (audit log cleared), 4719 (system audit policy changed),
  4735 (security-enabled local group changed)
- [ ] **Sysmon:** 6 (driver loaded), 15 (FileCreateStreamHash / ADS detection),
  16 (Sysmon config change), 24 (clipboard change),
  26 (file-delete logged)
- [ ] **System:** 7031 (service crash), 7034 (service unexpectedly terminated)
- [ ] **PowerShell:** 4105/4106 (script start/stop), 40961/40962 (engine
  start/stop)

### Event Sequence Validation
- [ ] `--validate` mode checks logical consistency: logon precedes activity,
  process create precedes terminate, ProcessGuids match, network events
  reference running processes
- [ ] Warnings on stderr (non-blocking) — lab authors can override when
  intentional (e.g. simulating log gaps)

---

## v0.8 — Export Formats & Detection Standards

Unlock real-world tool pipelines: forensic tools get binary EVTX, Splunk
cohorts get CIM-mapped JSON, and detection rules speak Sigma.

### Binary EVTX Export
- [ ] `--format evtx` exporter producing valid `.evtx` files (EVTX file header,
  chunk headers, event records with BinXML encoding)
- [ ] Output directly loadable by Chainsaw, Hayabusa, `Get-WinEvent`,
  EVTX Explorer, and Windows Event Viewer
- [ ] One `.evtx` file per host/channel pair (matching current XML convention)

### Sigma Rule Integration
- [ ] Replace or supplement built-in detection rules with Sigma YAML rules
- [ ] Evaluate Sigma rules against generated events via `pySigma`
- [ ] Lab authors embed Sigma rules as expected detections; `artiforge check`
  reports Sigma coverage alongside built-in rules
- [ ] Ship a curated starter set of Sigma rules mapped to existing labs

### Splunk CIM / HEC Export
- [ ] `--format splunk` outputs HEC-compatible JSON with CIM field mapping
  (`src`, `dest`, `user`, `action`, `app`, `object_category`)
- [ ] Includes `index` and `sourcetype` metadata for direct Splunk ingestion
- [ ] Mapping table between ECS fields and CIM fields for maintainability

---

## v0.9 — Realism & Cross-Platform

Noise that feels like a real enterprise, timezone-aware multi-region logs,
and a first-class Linux audit channel.

### Realistic Noise Engine v2
- [ ] New noise categories: file operations (Sysmon 11), registry reads
  (Sysmon 13), service start/stop (System 7036), network connections
  (Sysmon 3), Windows Update traffic (DNS + HTTP)
- [ ] Temporal profiles: business-hours clustering (08:00–18:00 local), quiet
  overnight periods, burst patterns around login/logout windows
- [ ] `noise_profile` key in lab YAML (presets: `office_hours`, `24x7_server`,
  `developer_workstation`, or custom)

### Multi-Timezone & Locale Support
- [ ] Optional `timezone` field per host in infrastructure block
- [ ] Engine stores canonical UTC internally; exports render per-host local time
- [ ] Enables training on timezone-unaware correlation pitfalls in
  multi-region environments

### Linux Auditd Channel
- [ ] New `linux_auditd` channel with generators for SYSCALL, EXECVE, PATH,
  SOCKADDR, USER_AUTH, USER_LOGIN, and CRED_ACQ record types
- [ ] Raw `audit.log` output format (key=value pairs matching auditd output)
- [ ] ECS-mapped NDJSON output (matching Auditbeat's schema)
- [ ] Platform-aware lab schema: labs can mix Windows and Linux hosts in the
  same infrastructure block

---

## v1.0 — Filesystem Artifacts, Scenario Library & Distribution

A standalone tool is useful; a curated library backed by forensic-grade
artifacts is a training platform.

### Filesystem Artifact Generation
- [ ] Prefetch files (`.pf`) with execution counts, timestamps, and referenced
  DLLs — correlated with Sysmon 1 process creation events
- [ ] Amcache registry hive entries for executed binaries
- [ ] $MFT stub records (filename, timestamps, parent directory) for key
  attack-path files
- [ ] Cross-artifact correlation: if Sysmon 1 says `mimikatz.exe` ran, the
  Prefetch and Amcache entries confirm it

### Scenario Library
- [ ] UC4 — Kerberoasting + Pass-the-Hash lateral movement
- [ ] UC5 — Supply chain: malicious npm package → C2 beacon
- [ ] UC6 — Ransomware: file encryption + shadow copy deletion
- [ ] UC7 — Insider threat: data staging + USB exfiltration
- [ ] UC8 — Living-off-the-land: wmic/mshta/regsvr32 chains
- [ ] UC9 — Cloud pivot: IMDS credential theft + lateral to S3
- [ ] UC10 — Active Directory: DCSync + Golden Ticket

### Distribution
- [ ] PyPI package (`pip install artiforge`)
- [ ] GitHub Actions CI: test matrix across Python 3.10/3.11/3.12
- [ ] Pre-built Docker image on GitHub Container Registry (`ghcr.io/d3vn0mi/artiforge`)
- [ ] Signed releases with checksums

---

## Contributing

Bug reports, new EID generators, and new lab scenarios are all welcome.
See `artiforge/labs/_template/DEVELOPMENT.md` for the lab authoring guide
and `artiforge/generators/security.py` for the generator pattern.
