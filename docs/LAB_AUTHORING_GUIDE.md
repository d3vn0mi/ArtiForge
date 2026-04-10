# ArtiForge Lab Authoring Guide

A step-by-step guide to creating your own attack simulation lab, with a comprehensive reference for the `lab.yaml` specification.

---

## Table of Contents

1. [Overview](#overview)
2. [Step-by-Step: Creating a Lab](#step-by-step-creating-a-lab)
   - [Step 1 - Plan Your Scenario](#step-1--plan-your-scenario)
   - [Step 2 - Scaffold the Lab](#step-2--scaffold-the-lab)
   - [Step 3 - Define Lab Metadata](#step-3--define-lab-metadata)
   - [Step 4 - Build the Infrastructure](#step-4--build-the-infrastructure)
   - [Step 5 - Design Attack Phases](#step-5--design-attack-phases)
   - [Step 6 - Write Events](#step-6--write-events)
   - [Step 7 - Add File Artifacts](#step-7--add-file-artifacts)
   - [Step 8 - Add Background Noise](#step-8--add-background-noise)
   - [Step 9 - Validate and Generate](#step-9--validate-and-generate)
3. [YAML Reference](#yaml-reference)
   - [Top-Level Structure](#top-level-structure)
   - [lab (Metadata)](#lab-metadata)
   - [infrastructure](#infrastructure)
   - [attack](#attack)
   - [Phases](#phases)
   - [Events](#events)
   - [File Artifacts](#file-artifacts)
   - [Noise](#noise)
4. [Supported Channels and EIDs](#supported-channels-and-eids)
5. [Event Field Reference](#event-field-reference)
6. [Timing Model](#timing-model)
7. [YAML Anchors for ProcessGuid Correlation](#yaml-anchors-for-processguid-correlation)
8. [Common Event Patterns](#common-event-patterns)
9. [CLI Commands](#cli-commands)
10. [Troubleshooting](#troubleshooting)

---

## Overview

An ArtiForge lab is a YAML file (`lab.yaml`) that describes an attack scenario: the hosts involved, the users, and a sequence of Windows events organised into phases. ArtiForge reads this file and generates realistic Windows Event Log XML and Elasticsearch NDJSON, complete with MITRE ATT&CK technique mappings and optional Navigator layers.

### What a Lab Produces

```
artifacts/
└── my-lab_20260219_091200/
    ├── events/                  # Windows XML event logs (one per host + channel)
    │   ├── WIN-WS1_Security.xml
    │   ├── WIN-WS1_Sysmon.xml
    │   └── WIN-DC1_Security.xml
    ├── elastic/
    │   └── bulk_import.ndjson   # Elasticsearch bulk import (ECS-mapped)
    ├── files/                   # Staged file artifacts (LNK, XSL, INF, etc.)
    │   ├── Resume_John_Smith.lnk.ps1
    │   └── style.xsl
    ├── navigator_layer.json     # MITRE ATT&CK Navigator layer
    └── IMPORT.md                # Import instructions
```

---

## Step-by-Step: Creating a Lab

### Step 1 - Plan Your Scenario

Before writing YAML, answer these questions:

1. **What attack are you simulating?** (e.g., spearphishing with LOLBIN execution chain, Kerberoasting, ransomware deployment)
2. **What MITRE ATT&CK techniques does it cover?** (e.g., T1566.001 Spearphishing Attachment, T1053.005 Scheduled Task)
3. **What hosts are involved?** (e.g., a victim workstation, a domain controller, a file server)
4. **What is the attack timeline?** Break it into phases with rough time gaps:
   - Phase 1: Initial access (T+0)
   - Phase 2: Persistence (T+15 min)
   - Phase 3: Lateral movement (T+60 min)
   - Phase 4: Exfiltration (T+90 min)
5. **What should the trainee find?** This shapes which events you generate and what clues to leave.

### Step 2 - Scaffold the Lab

Use the built-in scaffolding command:

```bash
artiforge new-lab --id uc4-kerberoast --name "Kerberoasting Attack" --output ~/labs
```

This creates:

```
~/labs/uc4-kerberoast/
├── lab.yaml          # Pre-filled template with FIXME markers
└── DEVELOPMENT.md    # Quick reference guide
```

**Lab ID rules:**
- Lowercase letters, digits, and hyphens only
- Must start with a letter or digit
- Examples: `uc4`, `ransomware-sim`, `insider-threat-01`

Open `lab.yaml` and replace every line marked `FIXME`.

### Step 3 - Define Lab Metadata

The `lab` section identifies your scenario:

```yaml
lab:
  id: uc4-kerberoast
  name: "Kerberoasting Attack"
  description: >
    Simulates a Kerberoasting attack where an authenticated domain user
    requests service tickets for SPN-enabled accounts, cracks them offline,
    and uses the compromised service account for lateral movement.
  mitre_version: "v18"
```

- `id` is used in CLI commands (`artiforge generate --lab uc4-kerberoast`) and output directories
- `name` appears in `artiforge list-labs` and the web UI
- `description` is shown in `artiforge info --lab uc4-kerberoast`
- `mitre_version` controls which ATT&CK version is used for Navigator layer export (default: `"v18"`)

### Step 4 - Build the Infrastructure

Define every host that will appear in the scenario. Each host key (e.g., `WIN-WS1`) is the name you'll reference in phases and events.

```yaml
infrastructure:
  domain: lab.local

  hosts:
    WIN-WS1:
      ip: 10.10.10.10
      fqdn: WIN-WS1.lab.local
      os: "Windows 10 22H2"
      sid_prefix: "S-1-5-21-3456789012-2345678901-1234567890"
      users:
        - username: j.martinez
          domain: LAB
          rid: 1001

    WIN-DC1:
      ip: 10.10.10.2
      fqdn: WIN-DC1.lab.local
      os: "Windows Server 2019"
      sid_prefix: "S-1-5-21-3456789012-2345678901-2222222222"
      users:
        - username: administrator
          domain: LAB
          rid: 500
        - username: svc_sql
          domain: LAB
          rid: 1105
```

**Key points:**
- `sid_prefix` must be unique per host (change the last group of digits)
- `rid` must be unique within each host's user list
- Every `host:` and `user:` referenced in events must exist here
- The first user in a host's list is used as the default when no user is specified

### Step 5 - Design Attack Phases

Each phase represents a stage of the attack. Phases are ordered by `offset_minutes` from `base_time`.

```yaml
attack:
  base_time: "2026-03-15T08:30:00Z"
  malicious_account: svc_backdoor

  phases:
    - id: 1
      name: "Initial Access - Compromised Credentials"
      mitre: [T1078.002]
      offset_minutes: 0
      host: WIN-WS1
      user: j.martinez
      events: [...]

    - id: 2
      name: "Discovery - SPN Enumeration"
      mitre: [T1558.003, T1087.002]
      offset_minutes: 12
      host: WIN-WS1
      user: j.martinez
      events: [...]

    - id: 3
      name: "Lateral Movement - Service Account"
      mitre: [T1021.001]
      offset_minutes: 45
      host: WIN-DC1
      user: svc_sql
      events: [...]
```

**Design tips:**
- Phase IDs must be unique integers (use 1, 2, 3, ...)
- `offset_minutes` determines when the phase begins relative to `base_time`
- Set `host` and `user` at the phase level to avoid repeating them on every event
- Individual events can override `host` and `user` for cross-host activity
- List MITRE technique IDs in `mitre` for Navigator layer export

### Step 6 - Write Events

Events are the core of your lab. Each event maps to a Windows Event Log entry.

```yaml
events:
  # User logs in
  - channel: Security
    eid: 4624
    offset_seconds: 0
    fields:
      TargetUserName: j.martinez
      TargetDomainName: LAB
      LogonType: '2'
      LogonProcessName: User32
      AuthenticationPackageName: Negotiate
      WorkstationName: WIN-WS1
      IpAddress: '-'
      IpPort: '-'
      ProcessName: 'C:\Windows\System32\winlogon.exe'

  # PowerShell launched
  - channel: Security
    eid: 4688
    offset_seconds: 30
    fields:
      SubjectUserName: j.martinez
      SubjectDomainName: LAB
      NewProcessName: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell.exe -ep bypass -f C:\Users\j.martinez\enum.ps1'
      ParentProcessName: 'C:\Windows\explorer.exe'

  - channel: Sysmon
    eid: 1
    offset_seconds: 30
    fields:
      ProcessGuid: &ps_guid '{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}'
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell.exe -ep bypass -f C:\Users\j.martinez\enum.ps1'
      ParentImage: 'C:\Windows\explorer.exe'
      User: 'LAB\j.martinez'
      IntegrityLevel: Medium

  # PowerShell script block captured
  - channel: PowerShell
    eid: 4104
    offset_seconds: 31
    fields:
      ScriptBlockText: |
        setspn -T lab.local -Q */*
        Add-Type -AssemblyName System.IdentityModel
        New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/WIN-DC1.lab.local:1433"
      MessageNumber: '1'
      MessageTotal: '1'
```

**Event writing rules:**
1. **Always pair Security 4688 with Sysmon 1** for process creation (use the same `offset_seconds`)
2. **Use YAML anchors** to share `ProcessGuid` between Sysmon events from the same process (see [YAML Anchors](#yaml-anchors-for-processguid-correlation))
3. **Fields override defaults** - any `fields:` value you provide replaces the generator's default; fields you omit get realistic defaults
4. **Quote numeric-looking strings** - values like `LogonType: '10'` must be quoted or YAML interprets them as integers

### Step 7 - Add File Artifacts

File artifacts are physical files the attacker drops or creates. Add them to any phase:

```yaml
file_artifacts:
  - type: raw
    dest: 'C:\Users\j.martinez\enum.ps1'
    content_template: |
      # SPN Enumeration Script
      setspn -T lab.local -Q */*

  - type: binary_placeholder
    dest: 'C:\Users\j.martinez\mimikatz.exe'
```

**Supported types:**

| Type | Description | Key Fields |
|------|-------------|------------|
| `lnk` | Windows shortcut | `lnk_target`, `lnk_args` |
| `xsl` | XSL stylesheet (LOLBAS execution) | `content_template` (optional) |
| `inf` | INF install script | `content_template` (optional) |
| `xml_task` | Scheduled task XML | `content_template` (optional) |
| `binary_placeholder` | README stub for staging a real binary | `dest` only |
| `raw` | Arbitrary text content | `content_template` |

### Step 8 - Add Background Noise

Real environments are noisy. Add background noise to make the lab more realistic and force trainees to filter signal from noise.

```yaml
attack:
  noise:
    - host: WIN-WS1
      spread_minutes: 120
      logon_pairs: 5
      process_spawns: 20
      dns_queries: 15

    - host: WIN-DC1
      spread_minutes: 120
      logon_pairs: 12
      process_spawns: 4
      dns_queries: 0
```

Noise events are tagged `phase_id=0` / `phase_name="noise"` and are automatically excluded from detection rule scoring. They appear in Kibana alongside attack events, requiring trainees to filter them out.

**Noise types:**
- `logon_pairs` - Security 4624 + 4634 pairs (interactive/network/RDP logons)
- `process_spawns` - Sysmon 1 events for benign processes (chrome.exe, svchost.exe, MsMpEng.exe, etc.)
- `dns_queries` - Sysmon 22 lookups for common domains (google.com, microsoft.com, windowsupdate.com, etc.)

### Step 9 - Validate and Generate

Follow this workflow to catch errors early:

```bash
# 1. Validate schema correctness
artiforge validate --lab-path ~/labs/uc4-kerberoast/lab.yaml

# 2. Run strict realism checks (placeholder hashes, timing order, logon precedence)
artiforge validate --lab-path ~/labs/uc4-kerberoast/lab.yaml --strict

# 3. Preview without writing files
artiforge generate --lab-path ~/labs/uc4-kerberoast/lab.yaml --dry-run

# 4. Generate artifacts
artiforge generate --lab-path ~/labs/uc4-kerberoast/lab.yaml

# 5. Check detection rule coverage
artiforge check --lab-path ~/labs/uc4-kerberoast/lab.yaml

# 6. View the lab in the browser
artiforge serve
```

**Useful generate options:**

```bash
# Override the timestamp
artiforge generate --lab uc4-kerberoast --base-time "2026-06-01T08:30:00Z"

# Deterministic output (same seed = identical output)
artiforge generate --lab uc4-kerberoast --seed 42

# Add organic timestamp jitter (events shift by up to +/- 5 seconds)
artiforge generate --lab uc4-kerberoast --jitter 5

# Generate only specific phases (useful during development)
artiforge generate --lab uc4-kerberoast --phases 1,2

# Output only XML or only Elasticsearch format
artiforge generate --lab uc4-kerberoast --format xml
artiforge generate --lab uc4-kerberoast --format elastic
```

---

## YAML Reference

### Top-Level Structure

Every `lab.yaml` has three required top-level sections:

```yaml
lab:              # Metadata: id, name, description, MITRE version
infrastructure:   # Hosts, IPs, SIDs, users
attack:           # Base time, phases, events, noise
```

### lab (Metadata)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | string | yes | - | Unique identifier. Lowercase letters, digits, hyphens only. |
| `name` | string | yes | - | Human-readable name shown in CLI and web UI. |
| `description` | string | no | `""` | 1-3 sentence scenario summary. Use `>` for multi-line. |
| `mitre_version` | string | no | `"v18"` | ATT&CK framework version for Navigator export. |
| `lab_schema_version` | string | no | `"1"` | Internal schema version. Set to `"1"`. |

### infrastructure

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domain` | string | yes | - | Active Directory domain name (e.g., `lab.local`). |
| `hosts` | dict | yes | - | Dictionary of hosts keyed by host name. |

**Host fields:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `ip` | string | yes | - | IPv4 address. |
| `fqdn` | string | yes | - | Fully-qualified domain name. |
| `os` | string | no | `"Windows 10"` | Operating system version. |
| `sid_prefix` | string | no | `"S-1-5-21-1111111111-2222222222-3333333333"` | SID prefix. Must be unique per host. |
| `users` | list | no | `[]` | Users who can log in to this host. |

**User fields:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `username` | string | yes | - | Username without domain prefix. |
| `domain` | string | yes | - | Domain or computer name. |
| `rid` | int | no | `1001` | Relative ID. Must be unique within the host. |

### attack

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `base_time` | ISO 8601 | yes | - | Anchor timestamp for all events. Overridable via `--base-time`. |
| `malicious_account` | string | no | `"svc_backup_admin"` | Default attacker account name for 4720/4732 events. |
| `phases` | list | no | `[]` | Attack phases. |
| `noise` | list | no | `[]` | Background noise specifications. |

### Phases

| Field | Type | Required | Default | Constraints | Description |
|-------|------|----------|---------|-------------|-------------|
| `id` | int | yes | - | Unique per lab | Phase identifier. |
| `name` | string | yes | - | - | Human-readable phase name. |
| `mitre` | list | no | `[]` | Technique IDs | MITRE ATT&CK technique IDs (e.g., `[T1566.001, T1204.002]`). |
| `offset_minutes` | int | no | `0` | >= 0 | Minutes after `base_time` when this phase starts. |
| `host` | string | no | `null` | Must exist in infrastructure | Default host for events in this phase. |
| `user` | string | no | `null` | Must exist in host's users | Default user for events in this phase. |
| `events` | list | no | `[]` | - | List of events. |
| `file_artifacts` | list | no | `[]` | - | List of file artifacts. |

### Events

| Field | Type | Required | Default | Constraints | Description |
|-------|------|----------|---------|-------------|-------------|
| `channel` | string | yes | - | See [Supported Channels](#supported-channels-and-eids) | Event log channel. |
| `eid` | int | yes | - | See [Supported EIDs](#supported-channels-and-eids) | Windows Event ID. |
| `offset_seconds` | int | no | `0` | >= 0 | Seconds after phase start. |
| `host` | string | no | inherited from phase | Must exist in infrastructure | Override the phase-level host. |
| `user` | string | no | inherited from phase | Must exist in host's users | Override the phase-level user. |
| `provider` | string | no | auto-derived from channel | - | Custom provider name override. |
| `fields` | dict | no | `{}` | - | Event field values. Your values override generator defaults. |
| `repeat` | int | no | `1` | >= 1 | Number of times to repeat this event. |
| `repeat_gap_seconds` | int | no | `30` | >= 0 | Seconds between repetitions. |
| `jitter_seconds` | int | no | `0` | >= 0 | Per-event timestamp jitter: +/- N seconds. |
| `repeat_jitter_seconds` | int | no | `0` | >= 0 | Jitter between repetitions: +/- N seconds per gap. |

### File Artifacts

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `type` | string | yes | - | One of: `lnk`, `xsl`, `inf`, `xml_task`, `binary_placeholder`, `raw`. |
| `dest` | string | yes | - | Windows-style destination path (for metadata/documentation). |
| `content_template` | string | no | type-specific default | Custom content for `xsl`, `inf`, `xml_task`, `raw` types. |
| `lnk_target` | string | no | `C:\Windows\System32\ie4uinit.exe` | Target executable for `lnk` type. |
| `lnk_args` | string | no | `"-BaseSettings"` | Arguments for `lnk` target. |

### Noise

| Field | Type | Required | Default | Constraints | Description |
|-------|------|----------|---------|-------------|-------------|
| `host` | string | yes | - | Must exist in infrastructure | Host to inject noise onto. |
| `spread_minutes` | int | no | `60` | >= 1 | Time window for scattering noise events. |
| `logon_pairs` | int | no | `0` | >= 0 | Number of 4624+4634 logon/logoff pairs. |
| `process_spawns` | int | no | `0` | >= 0 | Number of Sysmon 1 benign process events. |
| `dns_queries` | int | no | `0` | >= 0 | Number of Sysmon 22 DNS query events. |

---

## Supported Channels and EIDs

| Channel | Provider | EIDs |
|---------|----------|------|
| **Security** | Microsoft-Windows-Security-Auditing | 4624, 4625, 4634, 4648, 4656, 4657, 4663, 4670, 4672, 4688, 4698, 4720, 4723, 4724, 4725, 4726, 4732, 4768, 4769, 4771, 4776, 4946, 4947, 5156, 5157 |
| **System** | Service Control Manager | 7036, 7045 |
| **Sysmon** | Microsoft-Windows-Sysmon | 1, 3, 5, 7, 8, 10, 11, 12, 13, 14, 17, 18, 22, 23, 25 |
| **Application** | Application | 1 |
| **PowerShell** | Microsoft-Windows-PowerShell | 4103, 4104 |
| **WMI** | Microsoft-Windows-WMI-Activity | 5857, 5860, 5861 |

---

## Event Field Reference

Each event generator populates default values for every field. Your `fields:` entries override those defaults. Below are the most commonly customised fields for key EIDs.

### Security Events

**4624 - Successful Logon**

| Field | Values | Notes |
|-------|--------|-------|
| `TargetUserName` | username | Who logged in |
| `TargetDomainName` | domain | Domain of the user |
| `LogonType` | `'2'` interactive, `'3'` network, `'10'` RDP | Must be quoted |
| `LogonProcessName` | `User32`, `NtLmSsp` | Interactive vs network |
| `AuthenticationPackageName` | `Negotiate`, `NTLM`, `Kerberos` | Auth protocol |
| `WorkstationName` | hostname | Source workstation |
| `IpAddress` | IP or `'-'` | Source IP for remote logons |
| `ProcessName` | full path | Usually `winlogon.exe` |

**4625 - Failed Logon**

| Field | Values | Notes |
|-------|--------|-------|
| `TargetUserName` | username | Account that failed |
| `LogonType` | `'2'`, `'3'`, `'10'` | Same as 4624 |
| `Status` | `'0xc000006d'` | Logon failure reason |
| `SubStatus` | `'0xc0000064'` unknown user, `'0xc000006a'` bad password | Specific sub-reason |
| `IpAddress` | IP | Source of failed attempt |

**4688 - Process Creation**

| Field | Values | Notes |
|-------|--------|-------|
| `SubjectUserName` | username | Who started the process |
| `SubjectDomainName` | domain | Domain context |
| `NewProcessName` | full path | Executable path |
| `CommandLine` | command | Full command line |
| `ParentProcessName` | full path | Parent process |
| `TokenElevationType` | `'%%1936'` default, `'%%1937'` full, `'%%1938'` limited | Must include `%%` prefix |

**4648 - Explicit Credentials (RunAs / RDP)**

| Field | Values | Notes |
|-------|--------|-------|
| `SubjectUserName` | username | Who used explicit creds |
| `TargetUserName` | username | Account being impersonated |
| `TargetServerName` | hostname | Target server |
| `ProcessName` | full path | Usually `mstsc.exe` or `runas.exe` |
| `IpAddress` | IP | Source IP |

**4698 - Scheduled Task Created**

| Field | Values | Notes |
|-------|--------|-------|
| `SubjectUserName` | username | Who created the task |
| `TaskName` | `'\TaskName'` | Backslash prefix convention |

**4720 - User Account Created**

| Field | Values | Notes |
|-------|--------|-------|
| `SubjectUserName` | creator | Account that performed creation |
| `TargetUserName` | new account | Newly created account |

**4732 - Member Added to Group**

| Field | Values | Notes |
|-------|--------|-------|
| `MemberName` | username | Account being added |
| `TargetUserName` | group name | Target group (e.g., `Administrators`) |

**4768 - Kerberos TGT Request**

| Field | Values | Notes |
|-------|--------|-------|
| `TargetUserName` | username | Account requesting TGT |
| `ServiceName` | `'krbtgt'` | Always krbtgt for TGT |
| `TicketEncryptionType` | `'0x12'` AES256, `'0x17'` RC4 | Encryption used |
| `Status` | `'0x0'` success | Result code |

**4769 - Kerberos Service Ticket Request**

| Field | Values | Notes |
|-------|--------|-------|
| `TargetUserName` | username | Requesting user |
| `ServiceName` | SPN | e.g., `MSSQLSvc/WIN-DC1:1433` |
| `TicketEncryptionType` | `'0x17'` RC4 is suspicious | Kerberoasting indicator |

### Sysmon Events

**EID 1 - Process Create**

| Field | Values | Notes |
|-------|--------|-------|
| `ProcessGuid` | `'{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}'` | Use YAML anchors to correlate |
| `Image` | full path | Executable image |
| `CommandLine` | command | Full command line |
| `ParentImage` | full path | Parent process |
| `User` | `'DOMAIN\username'` | Process owner |
| `IntegrityLevel` | `Low`, `Medium`, `High`, `System` | Process integrity |
| `Hashes` | `'MD5=...,SHA256=...'` | File hashes |

**EID 3 - Network Connection**

| Field | Values | Notes |
|-------|--------|-------|
| `ProcessGuid` | anchor reference | Link to Sysmon 1 |
| `Image` | full path | Process making connection |
| `Protocol` | `tcp`, `udp` | Network protocol |
| `Initiated` | `'true'`, `'false'` | Outbound vs inbound |
| `SourceIp` / `DestinationIp` | IPs | Endpoints |
| `DestinationPort` | port number | e.g., `443`, `3389` |
| `DestinationPortName` | `https`, `ms-wbt-server` | Service name |

**EID 7 - Image Loaded (DLL)**

| Field | Values | Notes |
|-------|--------|-------|
| `Image` | process path | Process loading the DLL |
| `ImageLoaded` | DLL path | DLL being loaded |
| `Signed` | `'true'`, `'false'` | Signature status |
| `SignatureStatus` | `'Valid'`, `'Expired'`, `'Unavailable'` | Signature validation |

**EID 8 - CreateRemoteThread**

| Field | Values | Notes |
|-------|--------|-------|
| `SourceImage` | injector path | Process performing injection |
| `TargetImage` | target path | Process being injected into (often `lsass.exe`) |

**EID 10 - ProcessAccess**

| Field | Values | Notes |
|-------|--------|-------|
| `SourceImage` | accessor path | Process accessing another |
| `TargetImage` | target path | Process being accessed (e.g., `lsass.exe`) |
| `GrantedAccess` | `'0x1010'`, `'0x1FFFFF'` | Access mask |

**EID 22 - DNS Query**

| Field | Values | Notes |
|-------|--------|-------|
| `QueryName` | domain | Domain being queried |
| `QueryStatus` | `'0'` success | DNS status code |
| `QueryResults` | `'type: 5 domain;IP;'` | Resolution results |

### System Events

**7045 - Service Installed**

| Field | Values | Notes |
|-------|--------|-------|
| `ServiceName` | name | Service name |
| `ImagePath` | path + args | Service executable and arguments |
| `ServiceType` | `'user mode service'`, `'kernel mode driver'` | Service type |
| `StartType` | `'auto start'`, `'demand start'`, `'boot start'` | Start mode |
| `AccountName` | `LocalSystem`, `NT AUTHORITY\SYSTEM` | Service account |

**7036 - Service State Change**

| Field | Values | Notes |
|-------|--------|-------|
| `param1` | service name | Name of the service |
| `param2` | `running`, `stopped` | New state |

### PowerShell Events

**4104 - Script Block Logging**

| Field | Values | Notes |
|-------|--------|-------|
| `ScriptBlockText` | script content | The captured PowerShell code |
| `MessageNumber` | `'1'` | Block number (for split scripts) |
| `MessageTotal` | `'1'` | Total blocks |

**4103 - Module Logging**

| Field | Values | Notes |
|-------|--------|-------|
| `Payload` | command details | Pipeline execution details |
| `ContextInfo` | formatted string | Host, engine version, command info |

### WMI Events

**5857 - WMI Provider Loaded**

| Field | Values | Notes |
|-------|--------|-------|
| `ProviderName` | name | WMI provider |
| `ProviderPath` | DLL path | Provider binary |

**5860/5861 - WMI Subscription**

| Field | Values | Notes |
|-------|--------|-------|
| `Namespace` | `'root\subscription'` | WMI namespace |
| `ESS` / `Consumer` / `PossibleCause` | details | Subscription components |

---

## Timing Model

```
base_time (e.g., 2026-03-15T08:30:00Z)
  |
  +--- Phase 1 (offset_minutes: 0)
  |      +--- Event A (offset_seconds: 0)    -> 08:30:00
  |      +--- Event B (offset_seconds: 5)    -> 08:30:05
  |      +--- Event C (offset_seconds: 10)   -> 08:30:10
  |
  +--- Phase 2 (offset_minutes: 15)
  |      +--- Event D (offset_seconds: 0)    -> 08:45:00
  |      +--- Event E (offset_seconds: 30)   -> 08:45:30
  |
  +--- Phase 3 (offset_minutes: 60)
         +--- Event F (offset_seconds: 5)    -> 09:30:05
```

**Timestamp calculation:**

```
event_time = base_time
           + (phase.offset_minutes * 60)
           + event.offset_seconds
           + random(+/- event.jitter_seconds)
```

**For repeated events:**

```
repeat_N_time = base_time
              + (phase.offset_minutes * 60)
              + event.offset_seconds
              + (N * repeat_gap_seconds)
              + random(+/- repeat_jitter_seconds)
```

**Example: C2 beacon with 5 callbacks, 30s apart, +/-12s jitter:**

```yaml
- channel: Sysmon
  eid: 3
  offset_seconds: 20
  repeat: 5
  repeat_gap_seconds: 30
  repeat_jitter_seconds: 12
  fields:
    DestinationIp: 198.41.192.227
    DestinationPort: 443
```

This generates connections at roughly: T+20s, T+50s, T+80s, T+110s, T+140s, each shifted by a random +/-12 seconds.

---

## YAML Anchors for ProcessGuid Correlation

In real Windows event logs, Sysmon events from the same process share a `ProcessGuid`. Use YAML anchors to replicate this:

```yaml
# Step 1: Define the anchor on Sysmon EID 1 (process creation)
- channel: Sysmon
  eid: 1
  offset_seconds: 5
  fields:
    ProcessGuid: &ps_guid '{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}'
    Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    CommandLine: 'powershell.exe -ep bypass'
    ParentImage: 'C:\Windows\explorer.exe'
    User: 'LAB\j.martinez'

# Step 2: Reference it on Sysmon EID 22 (DNS query by the same process)
- channel: Sysmon
  eid: 22
  offset_seconds: 7
  fields:
    ProcessGuid: *ps_guid
    Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    QueryName: evil.example.com

# Step 3: Reference it on Sysmon EID 3 (network connection by the same process)
- channel: Sysmon
  eid: 3
  offset_seconds: 8
  fields:
    ProcessGuid: *ps_guid
    Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    DestinationIp: 1.2.3.4
    DestinationPort: 443
```

**Generating a GUID:**

```bash
python3 -c "import uuid; print('{' + str(uuid.uuid4()).upper() + '}')"
```

**Rules:**
- The anchor (`&name`) must appear before any reference (`*name`) in the YAML file
- GUID format: `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (uppercase hex, wrapped in braces)
- If you don't set `ProcessGuid`, ArtiForge generates a random one per event (meaning they won't correlate)

---

## Common Event Patterns

### Pattern 1: Interactive Logon + Process Execution

```yaml
# User logs in interactively
- channel: Security
  eid: 4624
  offset_seconds: 0
  fields:
    TargetUserName: victim.user
    TargetDomainName: LAB
    LogonType: '2'
    ProcessName: 'C:\Windows\System32\winlogon.exe'

# Admin privileges assigned
- channel: Security
  eid: 4672
  offset_seconds: 1
  fields:
    SubjectUserName: victim.user
    SubjectDomainName: LAB

# Process spawned (always pair 4688 + Sysmon 1)
- channel: Security
  eid: 4688
  offset_seconds: 5
  fields:
    SubjectUserName: victim.user
    NewProcessName: 'C:\Windows\System32\cmd.exe'
    CommandLine: 'cmd.exe /c whoami'
    ParentProcessName: 'C:\Windows\explorer.exe'

- channel: Sysmon
  eid: 1
  offset_seconds: 5
  fields:
    Image: 'C:\Windows\System32\cmd.exe'
    CommandLine: 'cmd.exe /c whoami'
    ParentImage: 'C:\Windows\explorer.exe'
    User: 'LAB\victim.user'
```

### Pattern 2: RDP Lateral Movement (Cross-Host)

```yaml
# On the SOURCE host: explicit credential use
- channel: Security
  eid: 4648
  offset_seconds: 0
  fields:
    SubjectUserName: attacker
    TargetUserName: admin
    TargetServerName: WIN-DC1
    ProcessName: 'C:\Windows\System32\mstsc.exe'
    IpAddress: 10.10.10.10

# On the SOURCE host: outbound RDP connection
- channel: Sysmon
  eid: 3
  offset_seconds: 1
  fields:
    Image: 'C:\Windows\System32\mstsc.exe'
    Protocol: tcp
    Initiated: 'true'
    SourceIp: 10.10.10.10
    DestinationIp: 10.10.10.2
    DestinationPort: 3389
    DestinationPortName: 'ms-wbt-server'

# On the TARGET host: RDP logon (override host)
- channel: Security
  eid: 4624
  offset_seconds: 5
  host: WIN-DC1
  user: admin
  fields:
    TargetUserName: admin
    TargetDomainName: LAB
    LogonType: '10'
    IpAddress: 10.10.10.10
    ProcessName: 'C:\Windows\System32\winlogon.exe'
```

### Pattern 3: Service Installation + C2 Beacon

```yaml
# Service installed
- channel: System
  eid: 7045
  offset_seconds: 0
  fields:
    ServiceName: WindowsUpdateSvc
    ImagePath: 'C:\ProgramData\update.exe tunnel run'
    ServiceType: 'user mode service'
    StartType: 'auto start'
    AccountName: LocalSystem

# Service started
- channel: System
  eid: 7036
  offset_seconds: 2
  fields:
    param1: WindowsUpdateSvc
    param2: running

# C2 process creation
- channel: Sysmon
  eid: 1
  offset_seconds: 5
  fields:
    ProcessGuid: &c2_guid '{DEADBEEF-1234-5678-9ABC-DEF012345678}'
    Image: 'C:\ProgramData\update.exe'
    CommandLine: '"C:\ProgramData\update.exe" tunnel run'
    ParentImage: 'C:\Windows\System32\services.exe'
    User: 'NT AUTHORITY\SYSTEM'
    IntegrityLevel: System

# Repeated C2 callbacks with realistic jitter
- channel: Sysmon
  eid: 3
  offset_seconds: 10
  repeat: 5
  repeat_gap_seconds: 60
  repeat_jitter_seconds: 15
  fields:
    ProcessGuid: *c2_guid
    Image: 'C:\ProgramData\update.exe'
    Protocol: tcp
    Initiated: 'true'
    SourceIp: 10.10.10.10
    DestinationIp: 198.51.100.1
    DestinationPort: 443
    DestinationPortName: https
```

### Pattern 4: Credential Access (LSASS Dump)

```yaml
# Process accessing LSASS
- channel: Sysmon
  eid: 10
  offset_seconds: 0
  fields:
    SourceImage: 'C:\Windows\Temp\procdump.exe'
    TargetImage: 'C:\Windows\System32\lsass.exe'
    GrantedAccess: '0x1FFFFF'
    SourceUser: 'NT AUTHORITY\SYSTEM'

# Dump file written
- channel: Sysmon
  eid: 11
  offset_seconds: 3
  fields:
    Image: 'C:\Windows\Temp\procdump.exe'
    TargetFilename: 'C:\Windows\Temp\lsass.dmp'
    User: 'NT AUTHORITY\SYSTEM'
```

### Pattern 5: Persistence via Registry Run Key

```yaml
# Registry key created
- channel: Sysmon
  eid: 12
  offset_seconds: 0
  fields:
    EventType: CreateKey
    Image: 'C:\Windows\System32\reg.exe'
    TargetObject: 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate'
    User: 'NT AUTHORITY\SYSTEM'

# Registry value set
- channel: Sysmon
  eid: 13
  offset_seconds: 1
  fields:
    Image: 'C:\Windows\System32\reg.exe'
    TargetObject: 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate'
    Details: 'C:\ProgramData\update.exe'
    User: 'NT AUTHORITY\SYSTEM'
```

---

## CLI Commands

| Command | Purpose |
|---------|---------|
| `artiforge new-lab --id ID --name NAME` | Scaffold a new lab from the template |
| `artiforge validate --lab ID` | Validate a lab's YAML schema |
| `artiforge validate --lab ID --strict` | Validate with realism checks |
| `artiforge generate --lab ID` | Generate all artifacts |
| `artiforge generate --lab-path PATH` | Generate from a lab.yaml outside the built-in directory |
| `artiforge generate --lab ID --dry-run` | Preview without writing files |
| `artiforge generate --lab ID --seed 42` | Deterministic generation |
| `artiforge generate --lab ID --jitter 5` | Add +/-5s timestamp jitter |
| `artiforge generate --lab ID --phases 1,2` | Generate only specific phases |
| `artiforge generate --lab ID --format xml` | Generate only XML output |
| `artiforge list-labs` | List all available labs |
| `artiforge info --lab ID` | Show detailed lab information |
| `artiforge check --lab ID` | Run detection rules against a lab |
| `artiforge diff --lab A --other B` | Compare two lab outputs |
| `artiforge graph --lab ID` | Show ProcessGuid/LogonId correlation graph |
| `artiforge navigator --lab ID` | Export MITRE ATT&CK Navigator layer |
| `artiforge coverage` | Show technique x lab coverage matrix |
| `artiforge serve` | Launch the web UI |
| `artiforge schema` | Print the JSON Schema for lab.yaml |

---

## Troubleshooting

| Error / Symptom | Cause | Fix |
|-----------------|-------|-----|
| `Host 'X' not found in infrastructure` | Event references a host not defined in `infrastructure.hosts` | Add the host to `infrastructure.hosts` |
| `Phase N event EID X has no host defined` | Neither the event nor the phase specifies a `host` | Add `host:` to the phase or event |
| Duplicate `record_id` warning | Bug or concurrent generation | Regenerate with `--seed` for consistency |
| YAML anchor `*name` has no value | The anchor `&name` appears after the reference | Move the `&name` definition before any `*name` references |
| `offset_seconds` validation error | Negative value | Offsets must be >= 0. Use a larger `offset_minutes` on the phase. |
| `EID X not implemented` | Unsupported Event ID | Check the [Supported EIDs table](#supported-channels-and-eids) |
| `LogonType` parsed as integer | Missing quotes | Use `LogonType: '10'` (quoted string) |
| `TokenElevationType: 1938` | Missing percent prefix | Use `'%%1938'` (with `%%` prefix, quoted) |
| Events appear at wrong timestamps | Confusion between phase offset and event offset | `offset_minutes` is on the phase, `offset_seconds` is on the event. Total = base_time + both. |
| ProcessGuid doesn't correlate events | Not using YAML anchors | Define `&anchor` on Sysmon 1, use `*anchor` on related events |
| `schema version mismatch` warning | Lab uses a different `lab_schema_version` | Set `lab_schema_version: "1"` in the `lab` section |
| Noise events mixed with attack events | Expected behavior | Noise is tagged `phase_id=0`. Use the web UI filter or Kibana query `NOT artiforge.phase_id:0` |
