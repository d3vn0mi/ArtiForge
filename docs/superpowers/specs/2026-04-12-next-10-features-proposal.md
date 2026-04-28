# ArtiForge — Next 10 Features Proposal

> **Date:** 2026-04-12
> **Status:** Draft — pending review
> **Focus:** Transform ArtiForge from an artifact generator into a training platform

---

## Current State

| Milestone | Status |
|-----------|--------|
| v0.1 — Foundation | Done |
| v0.2 — Event Coverage Expansion | Done |
| v0.3 — Realism & Noise | Done |
| v0.4 — Lab Quality & Tooling | Done |
| v0.5 — MITRE ATT&CK Integration & Web UI | Done |
| v0.6 — Kibana Realism | Done |
| v0.7–v0.8 | **Undefined — this proposal** |
| v0.9 — Distribution | Planned |
| v1.0 — Scenario Library | Planned |

**What exists today:**
- 50+ event generators across 6 Windows log channels
- 2 labs (UC3 + UC3N) with trainer guide, trainee brief, and tiered hints (markdown)
- 13 built-in detection rules with coverage reporting
- Web UI with timeline, trainer dashboard, and overview tabs
- XML and Elasticsearch NDJSON export
- MITRE ATT&CK Navigator layers + coverage matrix
- Docker-based Elastic/Kibana lab environment

**Key gap:** ArtiForge generates excellent artifacts but has no structured trainee workflow, no auto-grading, and only 2 lab scenarios.

---

## Proposed Features

### 1. UC8 — Living-off-the-Land Lab

| | |
|---|---|
| **Size** | **M** |
| **Milestone** | v0.7 |

A multi-phase attack chain using only built-in Windows binaries (LOLBins):
`wmic` → `mshta` → `regsvr32` → `certutil` for download → `rundll32` for execution.

**Why now:** Directly extends the LOLBin theme from UC3. All required generators
already exist (Sysmon 1/3/7, Security 4688, PowerShell 4104). Detection rule DR-001
already checks for these binaries. Mostly YAML authoring + trainer/trainee docs.

**Training value:** LOLBin abuse is one of the hardest categories for junior analysts
to detect because the binaries are legitimate. Forces trainees to reason about
*context* (parent process, command-line args, network connections) rather than
just binary name.

---

### 2. UC4 — Kerberoasting + Pass-the-Hash

| | |
|---|---|
| **Size** | **M** |
| **Milestone** | v0.7 |

AD-focused attack: service account enumeration → Kerberoasting (TGS request for
offline cracking) → Pass-the-Hash lateral movement → privilege escalation.

**Why now:** Kerberos generators (4768/4769/4771) and ProcessAccess (Sysmon 10)
already ship. This is one of the most common real-world AD attack paths and a
staple of security certifications (OSCP, BTL1, CCD).

**Training value:** Teaches trainees to correlate Kerberos ticket requests with
unusual service accounts, spot RC4 vs AES256 encryption downgrades, and trace
lateral movement through logon events.

---

### 3. Hunt Task Schema in Lab YAML

| | |
|---|---|
| **Size** | **S** |
| **Milestone** | v0.7 |

Formalize the hunt tasks currently written as free-form markdown (`trainee_brief.md`,
`trainer_guide.md`) into a structured YAML schema within `lab.yaml`:

```yaml
hunt_tasks:
  - id: HT-01
    title: "Identify the initial access vector"
    objective: "Determine how the attacker gained initial access"
    difficulty: easy
    hints:
      - "Look for Sysmon EID 1 events with unusual parent processes"
      - "Filter by the earliest timestamp in the attack window"
    expected_findings:
      - field: process.name
        value: "mshta.exe"
      - field: process.parent.name
        value: "explorer.exe"
    scoring:
      max_points: 10
      partial_credit:
        - condition: "identified_process"
          points: 5
        - condition: "identified_parent_chain"
          points: 5
    kql_reference: "process.name: mshta.exe AND host.name: WIN-WS1"
```

**Why now:** Structured tasks enable every downstream feature (auto-grading,
trainee UI, difficulty tiers). Small effort, high leverage.

**Training value:** Consistent task format across all labs. Machine-readable
for future automation.

---

### 4. Trainee Mode for Web UI

| | |
|---|---|
| **Size** | **M** |
| **Milestone** | v0.8 |

Add a `/trainee/<lab_id>` route to the Flask web UI:

- Shows: scenario brief, hunt task list, submission form, hint reveal buttons
- Hides: event timeline, detection results, trainer guide, answer keys
- Trainer dashboard remains at `/lab/<lab_id>` (unchanged)

Trainee submits answers per task (free-text + optional KQL). Answers stored
in-memory (no database yet — that's feature #10).

**Why now:** The web UI already exists with Flask + Jinja2. This is a new route
with a new template, not a rewrite. Makes ArtiForge usable in a classroom
setting without trainees accidentally seeing answers.

**Training value:** Trainees get a focused interface. Trainers can project the
dashboard without revealing answers.

---

### 5. Auto-Grading Engine

| | |
|---|---|
| **Size** | **L** |
| **Milestone** | v0.8 |

Given structured hunt tasks (feature #3), automatically score trainee submissions:

- **KQL validation:** Parse submitted KQL, run against the generated bundle,
  check if results match expected findings
- **IOC extraction:** Regex match for IPs, hashes, filenames, usernames
- **Free-text scoring:** Keyword/phrase matching against expected answer fields
- **Partial credit:** Configurable per task (e.g., 5 pts for process name,
  5 pts for full parent chain)

Output: per-task score + total score + feedback on missed findings.

**Why now:** Depends on feature #3 (structured tasks). This is the feature that
turns ArtiForge from "generate and hope" into "generate, assign, grade."

**Training value:** Instant feedback for trainees. Trainers can run labs with
30+ students without manually grading each submission.

---

### 6. Difficulty Tiers

| | |
|---|---|
| **Size** | **S** |
| **Milestone** | v0.7 |

Formalize what UC3 → UC3N does manually into a first-class feature:

- Per-lab `difficulty` field: `easy`, `medium`, `hard`
- Noise multiplier presets tied to difficulty
- Hint visibility: easy = all hints shown, medium = first hint only, hard = no hints
- CLI flag: `--difficulty easy|medium|hard`

```yaml
difficulty_presets:
  easy:
    noise_multiplier: 0
    hints_visible: all
  medium:
    noise_multiplier: 1
    hints_visible: first_only
  hard:
    noise_multiplier: 3
    hints_visible: none
    red_herrings: true
```

**Why now:** Eliminates the need for separate lab variants (UC3 vs UC3N).
One lab YAML, three difficulty levels. Small schema change + CLI flag.

**Training value:** Same lab scales from onboarding to advanced training.
Trainers don't maintain duplicate labs.

---

### 7. UC6 — Ransomware

| | |
|---|---|
| **Size** | **M** |
| **Milestone** | v0.9 |

Ransomware simulation: initial access → privilege escalation → `vssadmin delete shadows`
→ mass file encryption (Sysmon 23 FileDelete + Sysmon 11 FileCreate with `.encrypted`
extension) → ransom note drop.

**Why now:** All core generators exist. High training demand — ransomware is the
#1 incident type most SOC teams will face.

**Training value:** Teaches trainees to identify pre-encryption indicators
(shadow copy deletion, service stops) and build a forensic timeline under
pressure.

---

### 8. PCAP Stub Generation

| | |
|---|---|
| **Size** | **M** |
| **Milestone** | v0.9 |

Generate minimal `.pcap` files from Sysmon EID 3 (NetworkConnect) events:

- Not full packet captures — connection metadata only (SYN/ACK stubs)
- Source/dest IP, port, protocol, timestamp from existing event data
- Compatible with Wireshark / tshark for network analysis exercises

New exporter module: `artiforge/exporters/pcap.py`

**Why now:** Network analysis is a core SOC skill but currently unaddressed.
Sysmon EID 3 events already contain all the metadata needed.

**Training value:** Trainees practice correlating network connections (Wireshark)
with endpoint telemetry (Kibana). Cross-tool correlation is a real-world skill.

---

### 9. Splunk HEC Export

| | |
|---|---|
| **Size** | **S** |
| **Milestone** | v0.8 |

Add `--format splunk` output: Splunk HTTP Event Collector (HEC) compatible JSON.

- Map ECS fields → Splunk CIM (Common Information Model)
- One NDJSON file, ingestible via `curl` to HEC endpoint
- Add Splunk quickstart section to docs

**Why now:** Many training programs use Splunk, not Elastic. This is a new
exporter (~200 lines) with field mapping, no architectural changes.

**Training value:** ArtiForge becomes SIEM-agnostic. Trainers aren't locked
into the Elastic ecosystem.

---

### 10. Session Management

| | |
|---|---|
| **Size** | **L** |
| **Milestone** | v0.9+ |

Trainer creates a "session" — a lab assignment with configuration:

- Unique `--seed` per trainee (everyone gets different-but-equivalent data)
- Trainee roster (name/email)
- Submission tracking per trainee per task
- Score aggregation and export (CSV/JSON)
- SQLite backend (no external database dependency)

Web UI additions:
- `/sessions` — list/create sessions
- `/session/<id>` — trainer view with trainee progress grid
- `/session/<id>/trainee/<name>` — individual trainee scorecard

**Why now:** This is the capstone "training platform" feature. Deferred because
it requires features #3, #4, and #5 as prerequisites.

**Training value:** Full classroom workflow — assign, track, grade, report.

---

## Recommended Milestone Grouping

### v0.7 — Lab Expansion + Structured Tasks

| # | Feature | Size |
|---|---------|------|
| 1 | UC8 — Living-off-the-Land lab | M |
| 2 | UC4 — Kerberoasting + Pass-the-Hash | M |
| 3 | Hunt task schema in lab YAML | S |
| 6 | Difficulty tiers | S |

**Theme:** More content + formalize training structure.

### v0.8 — Trainee Experience

| # | Feature | Size |
|---|---------|------|
| 4 | Trainee mode for Web UI | M |
| 5 | Auto-grading engine | L |
| 9 | Splunk HEC export | S |

**Theme:** Make ArtiForge usable as a classroom tool.

### v0.9+ — Platform & Polish

| # | Feature | Size |
|---|---------|------|
| 7 | UC6 — Ransomware lab | M |
| 8 | PCAP stub generation | M |
| 10 | Session management | L |

**Theme:** Broaden content, add network artifacts, full session tracking.

---

## T-Shirt Size Legend

| Size | Effort | Typical Scope |
|------|--------|---------------|
| **S** | 1–2 days | Schema change, new CLI flag, single-file exporter |
| **M** | 3–5 days | New lab scenario (YAML + docs), new UI route, new module |
| **L** | 1–2 weeks | Cross-cutting feature touching models, CLI, web UI, and tests |
