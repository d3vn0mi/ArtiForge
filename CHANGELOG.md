# Changelog

All notable changes to ArtiForge are documented in this file.

## [1.0.0] — 2026-04-18

### Added — Filesystem Artifact Generation
- Prefetch binary (`.pf`) generator — Windows 10+ v30 format, parseable by PECmd
- Amcache JSON generator — matching AmcacheParser field format
- $MFT JSON generator — matching MFTECmd field format
- `forensic_artifacts: true` opt-in on AttackSpec (auto-derived from process events)
- Cross-artifact correlation — all three reference same executables with consistent timestamps

### Added — UC3E Enhanced Lab
- Showcase lab using all v0.7–v1.0 features
- `noise_profile: office_hours` / `24x7_server` with per-host overrides
- 5 bundled Sigma rules (LOLBin, service, tunnel, PowerShell archive, RDP)
- Session/process correlation labels, new EIDs (4697, 5157, 4104)

### Added — Web Dashboard Redesign
- Tactical SOC aesthetic (JetBrains Mono, DM Sans, cyan/amber/green accents)
- Scenario browser with dossier-style cards showing hosts, techniques, features
- Platform stats bar with aggregate metrics

## [0.9.0] — 2026-04-17

### Added — Noise Engine v2
- 5 new noise types: file operations, registry writes, service changes, network connections, Windows Update (correlated 3-event burst)
- 3 temporal profiles: `office_hours`, `24x7_server`, `developer_workstation`
- Hour-weighted distribution curves (events cluster around business hours)
- Preset system with per-field overrides via `noise_profile` key

### Added — Linux Auditd Channel
- `platform` field on Host (`windows` | `linux`, defaults to `windows`)
- 7 auditd record type generators: SYSCALL, EXECVE, PATH, SOCKADDR, USER_AUTH, USER_LOGIN, CRED_ACQ
- String EID aliases in lab YAML (`eid: USER_AUTH`)
- Raw `audit.log` exporter (`--format auditd`)
- ECS-mapped NDJSON output matching Auditbeat schema
- Mixed Windows + Linux hosts in same lab infrastructure

## [0.8.0] — 2026-04-17

### Added — Binary EVTX Export
- `evtxforge` — pure-Python EVTX writer library (`libs/evtxforge/`)
- BinXML encoder with inline element serialization
- CRC32 checksums, FILETIME encoding, chunk management
- `--format evtx` producing valid `.evtx` files per (host, channel)
- Compatible with Chainsaw, Hayabusa, Windows Event Viewer

### Added — Lightweight Sigma Rule Evaluator
- Custom Sigma YAML evaluator — no pySigma dependency
- Supports selections, modifiers (contains/startswith/endswith/all), wildcards
- Conditions: and, or, not, 1 of, all of (~80% Sigma syntax coverage)
- `artiforge check --sigma-dir` and `--sigma-only` flags
- Auto-discovery of `sigma/` directory in lab folders
- 3 starter Sigma rules shipped with UC3

## [0.7.0] — 2026-04-12

### Added — Event Correlation Engine
- `CorrelationContext` per (phase, host) — shared identifiers across related events
- Three-tier field precedence: YAML fields > correlation context > random default
- `session` and `process` labels on EventSpec for multi-session scenarios
- Security 4624 as session producer, Sysmon 1 as process producer
- Parent-child process chains auto-link via context

### Added — Expanded Event Coverage (16 new EIDs)
- Security: 1102 (audit log cleared), 4697 (service install), 4703 (token adjusted), 4719 (audit policy changed), 4735 (group changed)
- Sysmon: 6 (driver loaded), 15 (ADS), 16 (config change), 24 (clipboard), 26 (file delete logged)
- System: 7031 (service crash), 7034 (service terminated)
- PowerShell: 4105/4106 (script start/stop), 40961/40962 (engine start/stop)

### Added — Event Sequence Validation
- Correlation-aware `--strict` checks: ProcessGuid matching, orphan logoff detection
- Realistic PID ranges (multiples of 4, categorized by process type)

## [0.6.0] — 2026-04-10

### Added — Kibana Realism
- ECS `labels.*` namespace mapping (matches real Winlogbeat data shape)
- `--no-meta` flag to strip training metadata from NDJSON output

## [0.5.0] — 2026-04-08

### Added — MITRE ATT&CK Integration & Web UI
- Navigator layer JSON export per lab
- Inline technique IDs on GeneratedEvent
- Coverage matrix (`artiforge coverage`)
- Browser-based lab viewer (`artiforge serve`)
- Timeline visualization with phase filtering
- Trainer dashboard with detection rule results

## [0.4.0] — 2026-04-06

### Added — Lab Quality & Tooling
- `artiforge check` — run 13 built-in detection rules
- `artiforge diff` — compare two bundles
- `artiforge graph` — phase dependency graph
- `artiforge validate --strict` — realism checks
- Schema versioning with compatibility warnings

## [0.3.0] — 2026-04-04

### Added — Realism & Noise
- `noise:` section in lab YAML with configurable logon pairs, process spawns, DNS queries
- `--seed` flag for deterministic generation
- `--jitter` global timestamp jitter
- Per-event `jitter_seconds` and `repeat_jitter_seconds`

## [0.2.0] — 2026-04-02

### Added — Event Coverage Expansion
- 15 new Security EIDs (Kerberos, account management, object access, WFP/firewall)
- 10 new Sysmon EIDs (process terminated, image loaded, remote thread, process access, registry, pipes, file delete, process tampering)
- WMI channel (5857, 5860, 5861)

## [0.1.0] — 2026-03-30

### Added — Foundation
- YAML-driven lab specification with Pydantic v2 validation
- Security, System, Sysmon, Application, PowerShell channels
- XML export (Windows Event Viewer compatible)
- Elasticsearch NDJSON bulk export (ECS-mapped)
- File artifact generation (LNK, XSL, INF, XML task, binary placeholder, raw)
- CLI: generate, validate, schema, list-labs, info, new-lab
- JSON Schema for VS Code YAML autocompletion
- Docker support with wrapper script
- UC3 "Egg-Cellent Resume" lab scenario
