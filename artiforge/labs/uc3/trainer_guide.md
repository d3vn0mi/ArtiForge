# UC3 "Egg-Cellent Resume" — Trainer Guide

> **INSTRUCTOR ONLY — Do not distribute to trainees**
>
> This document contains expected findings, tiered hints, and debrief talking points
> for all five hunt tasks. Trainees receive only `trainee_brief.md`.

---

## Scenario Overview

A spear-phishing email delivered a weaponised `.lnk` file disguised as a job application
(`Resume_John_Smith.lnk`) to `marcus.webb` on `WIN-WS1`. Clicking it triggered a
**LOLBAS execution chain** (ie4uinit → msxsl → cmd) that ran wholly within signed
Windows binaries, evading most AV solutions. The attacker then:

1. Installed a **scheduled task** disguised as a Microsoft Edge updater for persistence
2. Exploited **CVE-2023-27532** against the Veeam Backup service to extract credentials
   and create a privileged local account on `WIN-BACKUP1`
3. Attempted **Cloudflared tunnel C2** registered as a spoofed Windows service
   (`Wuauserv_Svc`) — blocked by egress firewall
4. Used the harvested `svc_backup_admin` credentials for **RDP lateral movement** to
   `WIN-WS2` and staged sensitive documents in a ZIP archive

**Total scenario duration:** ~2 hours 5 minutes  
**Affected hosts:** WIN-WS1 (primary), WIN-BACKUP1 (pivot target), WIN-WS2 (lateral target)

---

## MITRE ATT&CK Coverage

| Phase | Technique | Tactic |
|-------|-----------|--------|
| 1 | T1204.002 User Execution: Malicious File | Execution |
| 1 | T1566.001 Phishing: Spearphishing Attachment | Initial Access |
| 1 | T1218 System Binary Proxy Execution | Defense Evasion |
| 1 | T1218.010 Regsvcs/Regasm (ie4uinit/msxsl) | Defense Evasion |
| 2 | T1053.005 Scheduled Task/Job | Persistence |
| 3 | T1210 Exploitation of Remote Services | Lateral Movement |
| 3 | T1136.001 Create Account: Local Account | Persistence |
| 3 | T1078 Valid Accounts | Defense Evasion |
| 4 | T1572 Protocol Tunneling | Command and Control |
| 4 | T1543.003 Create or Modify System Process: Windows Service | Persistence |
| 4 | T1036.004 Masquerading: Masquerade Task or Service | Defense Evasion |
| 5 | T1021.001 Remote Services: Remote Desktop Protocol | Lateral Movement |
| 5 | T1550.002 Use Alternate Authentication Material: Pass the Hash | Defense Evasion |
| 5 | T1560.001 Archive Collected Data: Archive via Utility | Collection |

---

## Environment Topology

```
Internet (egress BLOCKED at firewall)
    ↑
    │ 443/TCP (argotunnel.com) — blocked
    │
WIN-WS1  (10.10.10.10) — marcus.webb's workstation, attack origin
    │
    ├─ 9401/TCP ──→ WIN-BACKUP1 (10.10.10.20) — Veeam Backup & Replication
    │
    └─ 3389/TCP ──→ WIN-WS2 (10.10.10.11) — file-staging workstation
```

Domain controller `WIN-DC1` (10.10.10.2) is present in the infrastructure but generates
no events in this scenario — a deliberate training point that not every host leaves
visible traces.

---

## Kibana Setup

- **Index pattern:** `winlogbeat-artiforge-uc3-*`
- **Time filter:** `2026-02-19 09:00:00` → `2026-02-19 11:30:00` UTC
- **Recommended columns:** `@timestamp`, `winlog.event_id`, `host.name`,
  `process.command_line`, `user.name`

---

## Hunt Task 1 — Initial Execution: LOLBAS Chain

### Objective
Identify the full execution chain that began execution on WIN-WS1, starting from the
user's interactive session, and trace every parent-child process relationship.

### Expected Findings
Trainees should identify:

| Time (UTC) | EID | Host | Detail |
|------------|-----|------|--------|
| 09:12:00 | 4624 | WIN-WS1 | marcus.webb interactive logon (Type 2) |
| 09:12:02 | Sysmon 11 | WIN-WS1 | `ie4uinit_setup.inf` dropped to %TEMP% |
| 09:12:03 | Sysmon 11 | WIN-WS1 | `style.xsl` dropped to C:\ProgramData\MicrosoftEdgeUpdate\ |
| 09:12:05 | 4688 + Sysmon 1 | WIN-WS1 | `ie4uinit.exe -BaseSettings` spawned by `explorer.exe` |
| 09:12:08 | 4688 + Sysmon 1 | WIN-WS1 | `msxsl.exe style.xsl data.xml` spawned by `ie4uinit.exe` |
| 09:12:10 | 4688 + Sysmon 1 | WIN-WS1 | `cmd.exe /c whoami && net user` spawned by `msxsl.exe` |

**Root cause:** A `.lnk` shortcut on marcus.webb's desktop targeting `ie4uinit.exe -BaseSettings`.
The INF file directs ie4uinit to execute msxsl, which transforms the XSL stylesheet to run cmd.

**Key anomalies to highlight:**
- `explorer.exe` spawning `ie4uinit.exe` with `-BaseSettings` is unusual (legitimate
  ie4uinit runs are rare on modern Windows)
- `ie4uinit.exe` spawning `msxsl.exe` is **never** legitimate
- `msxsl.exe` processing files from `C:\ProgramData\` is a strong IOC
- `cmd.exe` command line contains `whoami && net user` — classic post-exploitation recon

### Tiered Hints
**Hint 1 (gentle):** Filter Kibana to `host.name: WIN-WS1` and look at Security EID 4688
events between 09:11 and 09:13. Sort by `@timestamp` ascending. What unusual process name
do you see as `NewProcessName`?

**Hint 2 (medium):** Search for `process.command_line: *ie4uinit*` — then pivot on the
`ParentProcessName` field. Can you extend the chain from that parent forward?

**Hint 3 (direct):** The chain is `explorer.exe → ie4uinit.exe → msxsl.exe → cmd.exe`.
Look for Sysmon EID 1 events to get the full command lines with parent relationships.
Also check Sysmon EID 11 for the dropped files that made this work.

### Debrief Talking Points
- LOLBAS (Living Off the Land Binaries and Scripts) abuses Windows-signed binaries that
  are already trusted by AV/EDR — no malware binary needed on disk at execution time
- `msxsl.exe` is a retired binary rarely present on modern systems but still found in
  enterprise environments — its parent should always be a build tool, never `ie4uinit`
- The `.lnk` file artifact (`Resume_John_Smith.lnk`) provides the delivery vector;
  Sysmon EID 11 shows the INF and XSL being written before execution
- Reference: The DFIR Report covers nearly identical chains in multiple 2023-2024 cases

---

## Hunt Task 2 — Persistence: Scheduled Task

### Objective
Identify what persistence mechanism was installed, how it was created, and where the
task definition is stored on disk.

### Expected Findings

| Time (UTC) | EID | Host | Detail |
|------------|-----|------|--------|
| 09:27:05 | Sysmon 11 | WIN-WS1 | `update.txt` written to C:\ProgramData\MicrosoftEdgeUpdate\ |
| 09:27:08 | 4688 + Sysmon 1 | WIN-WS1 | `schtasks /Create /TN "MicrosoftEdgeUpdateTaskMachineUA" /XML ... /F` |
| 09:27:09 | **4698** | WIN-WS1 | Scheduled task created: `\MicrosoftEdgeUpdateTaskMachineUA` |
| 09:27:10 | Sysmon 13 | WIN-WS1 | Registry key set under TaskCache\Tasks |

**Key anomalies:**
- `schtasks /Create /XML` loading a task definition from a `.txt` file — the extension
  disguises an XML task definition
- Task name `MicrosoftEdgeUpdateTaskMachineUA` closely mimics a legitimate Edge updater task
- Task definition file stored in `C:\ProgramData\MicrosoftEdgeUpdate\` alongside the XSL
  from Phase 1 — same staging directory
- 4698 `TaskContent` field contains the full XML with trigger and action details

### Tiered Hints
**Hint 1:** Search for Security EID `4698` — this is the "Scheduled Task Created" event.
What is the `TaskName` field?

**Hint 2:** Now search for `process.command_line: *schtasks*`. What flag in the command
line points to how the task was defined (hint: not `/TR`)?

**Hint 3:** The `/XML` flag imports a task definition from a file. Find the Sysmon EID 11
event just before the schtasks execution to see where that file was written.
Also check Sysmon EID 13 for the resulting registry persistence entry.

### Debrief Talking Points
- Security EID 4698 is the gold-standard detection for scheduled task creation — always
  enriched with the full XML, making it trivial to analyse the trigger and action
- Using `/XML` to import a task definition is less common than `/TR` and should be hunted
  specifically — it allows complex trigger configurations without command-line exposure
- The `.txt` extension on the XML file is a simple but effective obfuscation for casual
  file inspection (e.g., `dir` output)
- Task name mimicry is covered by T1036: defenders should baseline legitimate Edge tasks
  (`MicrosoftEdgeUpdateTaskMachineCore`, `...UA`) and alert on near-matches

---

## Hunt Task 3 — Veeam Pivot: Credential Extraction

### Objective
Determine how the attacker moved from WIN-WS1 to WIN-BACKUP1, what vulnerability was
exploited, and what the outcome was on WIN-BACKUP1.

### Expected Findings

| Time (UTC) | EID | Host | Detail |
|------------|-----|------|--------|
| 10:12:00 | Sysmon 3 | WIN-WS1 | `cmd.exe` connects to 10.10.10.20:**9401**/TCP |
| 10:14:00 | 4688 + Sysmon 1 | WIN-WS1 | `wmic /node:10.10.10.20 process list brief` |
| 10:15:00 | **4720** | WIN-BACKUP1 | Account `svc_backup_admin` created by `VEEAMBACKUP$` |
| 10:15:05 | **4732** | WIN-BACKUP1 | `svc_backup_admin` added to Administrators group |
| 10:15:20 | 4648 | WIN-BACKUP1 | Explicit credentials used from 10.10.10.10 |

**Root cause:** CVE-2023-27532 — unauthenticated API endpoint on TCP 9401 in
Veeam Backup & Replication exposes credential material. The Veeam service account
(`VEEAMBACKUP$`) is then used to create a new local admin, leaving `VEEAMBACKUP$`
as the Subject in 4720/4732.

**Key anomalies:**
- TCP 9401 is the Veeam `Veeam.Backup.Service.exe` management port — non-standard
  and not normally accessed from workstations
- `VEEAMBACKUP$` (machine account) creating a local user is never legitimate
- New account immediately added to Administrators within 5 seconds of creation
- 4648 records credential use from WS1 IP shortly after account creation

### Tiered Hints
**Hint 1:** Look at Sysmon EID 3 (network connection) events on WIN-WS1 around 10:12.
What is the `DestinationPort`? Is this port associated with a known service or CVE?

**Hint 2:** Switch focus to WIN-BACKUP1. Search for Security EID 4720 and 4732. Who
is the `SubjectUserName` creating the account? Is this what you would expect?

**Hint 3:** TCP 9401 is CVE-2023-27532 (Veeam Backup & Replication). The unauthenticated
API exposes hashed credentials. The `VEEAMBACKUP$` account is the Veeam service identity
used to make the system changes. Check the 4648 event for confirmation of lateral use
of the extracted credentials.

### Debrief Talking Points
- CVE-2023-27532 (CVSS 7.5) was patched in March 2023; unpatched Veeam instances
  remain common in enterprise environments
- TCP 9401 should never be reachable from end-user workstations — network segmentation
  is the primary control here
- Machine accounts (`HOSTNAME$`) creating human-readable accounts is an extremely rare
  and high-fidelity IOC
- The 5-second gap between 4720 and 4732 mirrors automated exploitation tooling

---

## Hunt Task 4 — C2: Cloudflared Tunnel Detection

### Objective
Identify the C2 mechanism installed, how it was disguised, and whether it successfully
established communication.

### Expected Findings

| Time (UTC) | EID | Host | Detail |
|------------|-----|------|--------|
| 11:02:05 | Sysmon 11 | WIN-WS1 | `update.exe` dropped to C:\ProgramData\Microsoft\Windows\ |
| 11:02:10 | 4688 + Sysmon 1 | WIN-WS1 | `sc create Wuauserv_Svc binPath= "...update.exe tunnel run --token..."` |
| 11:02:12 | **7045** | WIN-WS1 | Service `Wuauserv_Svc` installed with `update.exe` binary path |
| 11:02:15 | 4688 | WIN-WS1 | `sc start Wuauserv_Svc` |
| 11:02:17 | Sysmon 1 | WIN-WS1 | `update.exe` spawned by `services.exe`, `OriginalFileName: cloudflared.exe` |
| 11:02:20–11:03:35 | Sysmon 3 ×5 | WIN-WS1 | Failed TCP 443 to 198.41.192.227 (region2.v2.argotunnel.com) |
| 11:03:50 | Application EID 1 | WIN-WS1 | cloudflared: "failed to connect to edge: dial tcp ... connection timed out" |

**Outcome:** C2 was **NOT** successfully established. All 5 connection attempts failed
due to egress firewall blocking outbound TCP 443 to Cloudflare's tunnel infrastructure.

**Key anomalies:**
- Service name `Wuauserv_Svc` mimics the legitimate Windows Update service (`wuauserv`)
- Binary path `C:\ProgramData\Microsoft\Windows\update.exe` — executables in ProgramData
  are not legitimate for Windows Update (correct path: C:\Windows\System32\wuauclt.exe)
- `OriginalFileName: cloudflared.exe` in Sysmon 1 reveals the binary's true identity
  despite the renamed file
- 5 failed outbound connections with exponential backoff (5s → 10s → 20s → 40s gaps)
  to `argotunnel.com` IPs — not expected from a Windows system
- `--token` argument in the command line / `ImagePath` is cloudflared's tunnel authentication

### Tiered Hints
**Hint 1:** Search for System EID `7045` — "A new service was installed." What are the
`ServiceName` and `ImagePath` values? Does the binary path match what you expect for
a service with that name?

**Hint 2:** Look at the `OriginalFileName` field in the Sysmon EID 1 event for
`update.exe`. What does this field reveal? Now search for Sysmon EID 3 events where
`Image` ends in `update.exe` — how many are there, and where do they connect?

**Hint 3:** The service name mimics `wuauserv` (Windows Update), but the binary is
cloudflared renamed to `update.exe`. The 5 Sysmon 3 events show failed TCP 443
connections to Cloudflare's tunnel network (argotunnel.com). The Application log
event confirms the failure reason. The C2 never connected.

### Debrief Talking Points
- Cloudflare Tunnel (`cloudflared`) is increasingly used as a C2 transport because:
  1. It uses TLS 443 (hard to block without breaking HTTPS)
  2. Traffic targets Cloudflare IPs (hard to blocklist)
  3. The binary is legitimate and signed by Cloudflare
- `OriginalFileName` from Sysmon 1 is extracted from the PE header and cannot be changed
  by simply renaming the file — this is one of the most reliable detection fields
- Egress firewall blocking outbound 443 to non-approved destinations is an effective
  countermeasure — visible here as 5 connection timeouts
- Service masquerading is T1036.004: defenders should maintain a baseline of legitimate
  service names and binary paths for comparison

---

## Hunt Task 5 — Lateral Movement and File Staging

### Objective
Trace the attacker's lateral movement from WIN-WS1 to the destination host, identify the
credentials used, and determine what was collected and staged.

### Expected Findings

| Time (UTC) | EID | Host | Detail |
|------------|-----|------|--------|
| 11:12:00 | Sysmon 3 | WIN-WS1 | `mstsc.exe` → 10.10.10.11:3389/TCP |
| 11:12:01 | 4648 | WIN-WS1 | Explicit creds: `svc_backup_admin` / `WIN-WS2`, via `mstsc.exe` |
| 11:12:05 | **4624** | WIN-WS2 | RDP logon Type 10, `svc_backup_admin`, from IP 10.10.10.10 |
| 11:12:06 | 4672 | WIN-WS2 | Special privileges assigned (local admin session) |
| 11:14:00 | 4688 + Sysmon 1 | WIN-WS2 | `powershell.exe -NoP -EP Bypass Compress-Archive ...docs_2026.zip` |
| 11:14:15 | Sysmon 11 | WIN-WS2 | `docs_2026.zip` created in svc_backup_admin's %TEMP% |
| 11:17:00 | 4634 | WIN-WS2 | RDP session logoff |

**Key findings:**
- Source: WIN-WS1, Destination: WIN-WS2 (10.10.10.11)
- Credential: `svc_backup_admin` — the account created in Phase 3 via the Veeam pivot
- Authentication: RDP (LogonType 10), Negotiate package — pass-the-hash or plaintext
- Staged file: `C:\Users\svc_backup_admin\AppData\Local\Temp\docs_2026.zip`
  containing contents of `C:\Users\svc_backup_admin\Documents\SensitiveDocs\`
- `-EP Bypass` flag disables PowerShell execution policy (a soft control)

### Tiered Hints
**Hint 1:** Look for Security EID `4624` with `LogonType: 10` on any host other than
WIN-WS1. Which host received an RDP logon, and what user account was used?

**Hint 2:** Before the 4624, look for a 4648 (Explicit Credentials Logon) on WIN-WS1.
What `TargetUserName` and `ProcessName` does it show? Now connect this credential to
what you found in Hunt Task 3.

**Hint 3:** The credential `svc_backup_admin` was created in Phase 3 on WIN-BACKUP1 and
reused here for RDP to WIN-WS2 (T1550.002 — pass-the-hash/credential reuse across hosts).
For collection: search Sysmon EID 11 on WIN-WS2 for file creation events. The `docs_2026.zip`
in %TEMP% is the staged archive ready for exfiltration.

### Debrief Talking Points
- The credential `svc_backup_admin` traces back to the Veeam pivot (Phase 3) — this is
  the full attack chain: phishing → LOLBAS → persistence → credential theft → C2 (failed)
  → lateral movement → data staging
- LogonType 10 (RemoteInteractive) is always RDP — combined with the source IP it gives
  clear provenance
- 4672 immediately after 4624 confirms `svc_backup_admin` has local admin rights on WIN-WS2
  (SeDebugPrivilege, SeBackupPrivilege, etc.)
- `powershell.exe -EP Bypass` is high-signal; combined with `Compress-Archive` and a
  destination path in %TEMP% it is a strong data-staging indicator
- Sysmon EID 11 shows the ZIP being created, but no exfiltration is recorded — trainees
  should note the file exists and discuss what exfil vector might follow

---

## Scoring Rubric

| Task | Full marks (10 pts each) | Partial (5 pts) | Zero |
|------|--------------------------|-----------------|------|
| 1 | All 3 hops identified with timestamps and parent chain | 2 of 3 hops | Only cmd.exe found |
| 2 | 4698 event + task name + /XML flag + .txt disguise identified | 4698 + task name only | Only scheduled task mentioned |
| 3 | TCP 9401 IOC + CVE named + account creation by VEEAMBACKUP$ | Account creation found, no CVE | "Something happened on BACKUP1" |
| 4 | Service masquerade identified + OriginalFileName + 5 failed attempts + outcome (no C2) | Service found + outbound traffic | Only "cloudflared" mentioned |
| 5 | Source/dest/credential/staged file all correct | 3 of 4 elements | Destination host only |

**Total: 50 points**

---

## Common Mistakes

| Mistake | How to address |
|---------|---------------|
| Trainee stops at cmd.exe, misses ie4uinit/msxsl | Ask: "What spawned cmd.exe? And what spawned that?" |
| Confusing MicrosoftEdgeUpdateTaskMachineUA with legitimate Edge task | Show the legitimate task list; note `/XML` flag vs `/TR` |
| Missing TCP 9401 — focuses only on account creation | Ask: "How did the attacker know the credentials? Look at network events on WS1 before the account was created." |
| Assuming C2 succeeded because a service was installed | Point to Application log event and Sysmon 3 failure pattern |
| Not connecting `svc_backup_admin` across Phase 3 and Phase 5 | Ask: "Where have you seen this username before?" |
| Missing the 4672 after RDP logon | Explain: every privileged logon generates 4672; its presence confirms admin rights |
