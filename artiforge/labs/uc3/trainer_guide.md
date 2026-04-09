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

### Evidence Reference

| Time (UTC) | EID | Host | Detail |
|------------|-----|------|--------|
| 09:12:00 | 4624 | WIN-WS1 | marcus.webb interactive logon (Type 2) |
| 09:12:02 | Sysmon 11 | WIN-WS1 | `ie4uinit_setup.inf` dropped to `%TEMP%` |
| 09:12:03 | Sysmon 11 | WIN-WS1 | `style.xsl` dropped to `C:\ProgramData\MicrosoftEdgeUpdate\` |
| 09:12:05 | 4688 + Sysmon 1 | WIN-WS1 | `ie4uinit.exe -BaseSettings` spawned by `explorer.exe` |
| 09:12:08 | 4688 + Sysmon 1 | WIN-WS1 | `msxsl.exe style.xsl data.xml` spawned by `ie4uinit.exe` |
| 09:12:10 | 4688 + Sysmon 1 | WIN-WS1 | `cmd.exe /c whoami && net user` spawned by `msxsl.exe` |

**MITRE:** T1566.001, T1204.002, T1218, T1218.010

---

### Q1. What process first executed as a result of the file being opened? What was its full command line, and what spawned it?

**Answer:** The first process to execute was `ie4uinit.exe`, with the full command line `ie4uinit.exe -BaseSettings`. It was spawned by `explorer.exe` at 09:12:05 UTC. The trigger was a malicious `.lnk` shortcut (`Resume_John_Smith.lnk`) on marcus.webb's desktop, which uses Windows ShellExecute to invoke its target — making `explorer.exe` the immediate parent.

**How to find it:**
```kql
winlog.event_id: (4688 or 1) and host.name: "WIN-WS1"
```
Sort ascending by `@timestamp`. On EID 4688, look at `winlog.event_data.NewProcessName` and `winlog.event_data.ParentProcessName`. On Sysmon EID 1, look at `winlog.event_data.Image`, `winlog.event_data.CommandLine`, and `winlog.event_data.ParentImage`. The first unusual entry is `C:\Windows\System32\ie4uinit.exe` with parent `C:\Windows\explorer.exe`.

**Hint 1:** Filter to `host.name: "WIN-WS1"` and EID 4688, sorted ascending, in the 09:11–09:13 window. What is the first unusual binary in `NewProcessName`?

**Hint 2:** Pull the Sysmon EID 1 event at the same timestamp — it gives the full command line and the parent's full path, not just the name.

**Trainer notes:** `.lnk` (shortcut) files invoke their target via `ShellExecute`, so `explorer.exe` always appears as the parent when a user double-clicks one. This is the correct and expected parent for user-initiated actions — the anomaly is not the parent but the target: `ie4uinit.exe -BaseSettings` has no legitimate use on Windows 10/11 outside of Internet Explorer setup, which no longer runs. Trainees who have never encountered LOLBAS may not immediately recognise `ie4uinit.exe` as suspicious — prompt them to ask whether they would expect a CV attachment to launch this binary.

---

### Q2. A chain of processes followed. List every process in the chain from first to last, including the parent-child relationships.

**Answer:**
```
explorer.exe
  └─ ie4uinit.exe -BaseSettings                                          [09:12:05]
       └─ msxsl.exe C:\ProgramData\MicrosoftEdgeUpdate\style.xsl data.xml  [09:12:08]
            └─ cmd.exe /c whoami && net user                               [09:12:10]
```

**How to find it:**
```kql
winlog.event_id: 1 and host.name: "WIN-WS1"
```
Sort ascending. For each event, use `winlog.event_data.Image` (the process) and `winlog.event_data.ParentImage` (its parent) to build the chain hop by hop. Starting from `cmd.exe`: its `ParentImage` is `msxsl.exe`; `msxsl.exe`'s `ParentImage` is `ie4uinit.exe`; `ie4uinit.exe`'s `ParentImage` is `explorer.exe`.

**Hint 1:** Use Sysmon EID 1 rather than 4688 — it includes `ParentImage` as the full binary path (not just a name), which is essential for distinguishing between two processes that share a name. Filter `host.name: "WIN-WS1"` and sort ascending.

**Hint 2:** If the chain is hard to see, work backwards: find `cmd.exe`, read its `ParentImage`, find that process, read its `ParentImage`, and repeat until you reach `explorer.exe`.

**Trainer notes:** The `msxsl.exe` hop is where most trainees get stuck — they either do not recognise the binary or cannot figure out what it does. Explain that `msxsl.exe` (Microsoft XML Source Transformation) transforms XML documents using XSLT stylesheets. A `<msxsl:script>` block inside the stylesheet executes arbitrary code — in this case, spawning `cmd.exe`. The key training point is that `msxsl.exe` is a signed Microsoft binary: it passes hash checks, application allowlisting, and most AV heuristics. Its only legitimate parent processes are developer tools and build pipelines — never `ie4uinit.exe`.

---

### Q3. What files were written to disk in the minutes immediately before or during this execution? Where were they written?

**Answer:** Two files were dropped to disk seconds before the execution chain started:
- `C:\Users\marcus.webb\AppData\Local\Temp\ie4uinit_setup.inf` — written at 09:12:02 UTC
- `C:\ProgramData\MicrosoftEdgeUpdate\style.xsl` — written at 09:12:03 UTC

**How to find it:**
```kql
winlog.event_id: 11 and host.name: "WIN-WS1"
```
Set the time filter to 09:11–09:13. The key field is `winlog.event_data.TargetFilename`, which gives the full path of each created file. The `winlog.event_data.Image` field shows the process that wrote the file — both were written by `explorer.exe` as part of the `.lnk` execution.

**Hint 1:** Sysmon EID 11 records every file creation. Filter to `host.name: "WIN-WS1"` in the 09:11–09:13 window. What does `TargetFilename` show for those two events?

**Hint 2:** One file has a `.inf` extension. `ie4uinit.exe` reads `.inf` files to decide what to run — this is the mechanism that hands off execution to `msxsl.exe`. Without this file existing on disk first, the chain cannot start.

**Trainer notes:** The staging directory `C:\ProgramData\MicrosoftEdgeUpdate\` is intentionally named to blend with the legitimate Microsoft Edge updater, which also uses a subdirectory with the same name. Without Sysmon EID 11, an analyst would only see the execution chain and might miss the pre-staged files entirely. This highlights a key training point: file write events are often the earliest observable indicator in a LOLBAS attack — the binary execution itself may look clean, but the files it reads are the real payload.

---

### Debrief

- **LOLBAS** abuses Windows-signed binaries that AV and EDR already trust — no custom malware binary needs to touch disk at execution time. The "malware" is the `.inf` and `.xsl` files.
- `msxsl.exe` is retired and rarely present on modern Windows; its parent should always be a developer build tool, never a shortcut launched by a user.
- The `.lnk` delivery vector (`Resume_John_Smith.lnk`) is the initial access artefact — Sysmon EID 11 shows the INF and XSL being staged before execution, providing the full delivery chain.
- Reference: The DFIR Report has documented nearly identical ie4uinit/msxsl chains in multiple intrusion reports from 2023–2024.



---

## Hunt Task 2 — Persistence: Scheduled Task

### Evidence Reference

| Time (UTC) | EID | Host | Detail |
|------------|-----|------|--------|
| 09:27:05 | Sysmon 11 | WIN-WS1 | `update.txt` written to `C:\ProgramData\MicrosoftEdgeUpdate\` |
| 09:27:08 | 4688 + Sysmon 1 | WIN-WS1 | `schtasks /Create /TN "MicrosoftEdgeUpdateTaskMachineUA" /XML ... /F` |
| 09:27:09 | 4698 | WIN-WS1 | Scheduled task created: `\MicrosoftEdgeUpdateTaskMachineUA` |
| 09:27:10 | Sysmon 13 | WIN-WS1 | Registry key set under `HKLM\...\TaskCache\Tasks\` |

**MITRE:** T1053.005

---

### Q1. What persistence mechanism was created, and what is its name?

**Answer:** A **Windows Scheduled Task** named `\MicrosoftEdgeUpdateTaskMachineUA` was created on WIN-WS1 at 09:27:09 UTC. The task is configured to run at user logon, ensuring it survives a reboot.

**How to find it:**
```kql
winlog.event_id: 4698 and host.name: "WIN-WS1"
```
Expand the event. The `winlog.event_data.TaskName` field contains `\MicrosoftEdgeUpdateTaskMachineUA`. The `winlog.event_data.TaskContent` field contains the full XML definition — including the trigger (logon) and the action (binary to execute).

**Hint 1:** Security EID 4698 fires every time a scheduled task is created, regardless of how it was created. Search for it on WIN-WS1. What does the `TaskName` field say?

**Hint 2:** Open the `TaskContent` field of the 4698 event. What `<Actions>` element is defined, and what binary does it point to?

**Trainer notes:** EID 4698 is one of the most reliable persistence detection events because it fires for every creation method — `schtasks.exe`, the Task Scheduler COM API, or even direct registry writes. The task name `MicrosoftEdgeUpdateTaskMachineUA` is deliberately chosen to mimic the real Edge updater task (`MicrosoftEdgeUpdateTaskMachineCore`). Trainees should be encouraged to look at the `TaskContent` field rather than just the task name — the full XML reveals the true trigger and action, and is immune to name obfuscation.

---

### Q2. How was it created? What command was run, and what is unusual about the method used?

**Answer:** The task was created with the following command at 09:27:08 UTC:
```
schtasks /Create /TN "MicrosoftEdgeUpdateTaskMachineUA" /XML "C:\ProgramData\MicrosoftEdgeUpdate\update.txt" /F
```
The unusual aspect is the `/XML` flag: instead of specifying the task action inline with the more common `/TR` flag, the attacker imported the full task definition from an external file (`update.txt`). This externalises the payload from the command line, making it invisible to detections that only inspect `process.command_line` for an executable path.

**How to find it:**
```kql
process.command_line: *schtasks* and host.name: "WIN-WS1"
```
On Sysmon EID 1 or EID 4688, the `process.command_line` / `winlog.event_data.CommandLine` field contains the full invocation with all flags. The `/XML` argument and the path to `update.txt` are both visible here.

**Hint 1:** Search for `process.command_line: *schtasks*` on WIN-WS1. Read the full command line — what flag, other than `/TN`, stands out?

**Hint 2:** The `/XML` flag points to a file. Check Sysmon EID 11 for that filename — when was it written to disk, and by what process?

**Trainer notes:** Most scheduled task detection rules specifically look for `/TR` (task run) in the command line, because that is the most common method and it puts the executable path directly in the shell history. The `/XML` technique bypasses this entirely — the command line contains no executable path, only a path to a file. This is why EID 4698's `TaskContent` field is critical: it captures the full XML regardless of creation method. Point trainees to the `/F` (force) flag as well — it silently overwrites any existing task with the same name, making re-establishment of persistence frictionless.

---

### Q3. Where is the configuration for this mechanism stored on disk? What is unusual about the file extension?

**Answer:** The task definition is stored at `C:\ProgramData\MicrosoftEdgeUpdate\update.txt`. The unusual aspect is the `.txt` extension: the file actually contains valid XML (a Windows Task Scheduler definition format), not plain text. Using `.txt` means the file appears benign on casual inspection — a `dir` listing, file manager browse, or antivirus file-type scan based on extension will not flag it as executable content.

**How to find it:**
```kql
winlog.event_id: 11 and host.name: "WIN-WS1"
```
Filter the time range to 09:26–09:28. The `winlog.event_data.TargetFilename` field shows `C:\ProgramData\MicrosoftEdgeUpdate\update.txt` written just before the `schtasks` command runs. Cross-reference with Sysmon EID 13 at 09:27:10 to see the resulting registry entry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\`.

**Hint 1:** Check Sysmon EID 11 in the 09:26–09:28 window on WIN-WS1. What file was written just before the `schtasks` command? What extension does it have?

**Hint 2:** Now look at the `/XML` argument in the schtasks command from Q2. The extension says `.txt` — but the XML task scheduler format is XML. Why would an attacker choose `.txt`?

**Trainer notes:** Windows Task Scheduler does not validate file extensions when importing via `/XML` — it reads the content, not the extension. A `.txt` file containing valid task XML imports without error. This is a low-effort obfuscation that defeats a surprising number of file-type-based detection rules. Also note the staging directory: `C:\ProgramData\MicrosoftEdgeUpdate\` is the same directory used in Task 1 for the `.xsl` payload, reinforcing that the attacker prepared all artefacts in a single location designed to blend with legitimate Edge update files. Sysmon EID 13 (Registry value set) shows the task being written to the Windows task cache — this can be used as a secondary detection if the file itself is deleted.

---

### Debrief

- EID 4698 is the gold-standard scheduled task detection — it always includes the full XML, making the true payload visible even when the creation method or file extension is obfuscated.
- The `/XML` import method is less common than `/TR` and should be a dedicated detection rule — the command line alone reveals no executable path.
- The `.txt` extension on an XML task definition is simple obfuscation that bypasses extension-based file-type checks; defenders should detect based on the EID 4698 `TaskContent`, not the file extension.
- Task name mimicry (T1036) is best detected by baselining legitimate scheduled tasks on clean builds and alerting on near-matches — not by blocklisting specific names.

---

## Hunt Task 3 — Veeam Pivot: Credential Extraction

### Evidence Reference

| Time (UTC) | EID | Host | Detail |
|------------|-----|------|--------|
| 10:12:00 | Sysmon 3 | WIN-WS1 | `cmd.exe` → 10.10.10.20:**9401**/TCP |
| 10:14:00 | 4688 + Sysmon 1 | WIN-WS1 | `wmic /node:10.10.10.20 process list brief` |
| 10:15:00 | 4720 | WIN-BACKUP1 | Account `svc_backup_admin` created — Subject: `VEEAMBACKUP$` |
| 10:15:05 | 4732 | WIN-BACKUP1 | `svc_backup_admin` added to Administrators group |
| 10:15:20 | 4648 | WIN-BACKUP1 | Explicit credentials used from 10.10.10.10 |

**MITRE:** T1210, T1136.001, T1078

---

### Q1. Which internal host did the attacker connect to from WIN-WS1, and on which port? What service or software typically listens on this port?

**Answer:** The attacker connected from WIN-WS1 to **WIN-BACKUP1 (10.10.10.20)** on **TCP port 9401** at 10:12:00 UTC. Port 9401 is the management API port for **Veeam Backup & Replication** (`Veeam.Backup.Service.exe`). This port is associated with **CVE-2023-27532**, an unauthenticated endpoint that exposes stored credential material.

**How to find it:**
```kql
winlog.event_id: 3 and host.name: "WIN-WS1"
```
Set the time range around T+60m (10:11–10:13). The key fields are `destination.ip` (10.10.10.20), `destination.port` (9401), and `winlog.event_data.Image` (the connecting process — `cmd.exe`). The `winlog.event_data.Initiated` field confirms the connection was outbound from WIN-WS1.

**Hint 1:** Look at Sysmon EID 3 events on WIN-WS1 around the 10:12 mark. What `destination.port` do you see, and which host is the destination?

**Hint 2:** Port 9401 is not a well-known port. Search for it alongside "Veeam" or "CVE-2023" — what vulnerability does it map to?

**Trainer notes:** Port 9401 is specific enough that trainees will not recognise it unless they have Veeam experience. Guide them to look it up — this is a realistic investigation skill. CVE-2023-27532 (CVSS 7.5, patched March 2023) allows an unauthenticated attacker to query the Veeam API and retrieve encrypted credentials stored by the backup service. The key detection principle here is network segmentation: TCP 9401 should never be reachable from an end-user workstation. Its presence in Sysmon EID 3 from `WIN-WS1` is itself a high-fidelity alert.

---

### Q2. What happened on that internal host as a result? Identify the specific event(s) and their details.

**Answer:** Two events fired on WIN-BACKUP1 within seconds of each other:
1. **EID 4720** at 10:15:00 UTC — a new local account named `svc_backup_admin` was created.
2. **EID 4732** at 10:15:05 UTC — `svc_backup_admin` was added to the local **Administrators** group.

Together these events confirm the attacker created a privileged backdoor account on the Veeam backup server 5 seconds after the network connection.

**How to find it:**
```kql
winlog.event_id: (4720 or 4732) and host.name: "WIN-BACKUP1"
```
On EID 4720: `winlog.event_data.TargetUserName` = `svc_backup_admin`. On EID 4732: `winlog.event_data.MemberName` = `svc_backup_admin`, `winlog.event_data.TargetUserName` = `Administrators`. Both events share the same `winlog.event_data.SubjectUserName`.

**Hint 1:** Switch your host filter from WIN-WS1 to WIN-BACKUP1. Search for EID 4720 and 4732 — what new account appears, and what group was it added to?

**Hint 2:** Note the timestamps of both events. How much time elapsed between account creation and group membership? What does that timing suggest?

**Trainer notes:** The 5-second gap between 4720 and 4732 is a strong indicator of automated tooling — a human manually creating an account and then opening Group Management would take considerably longer. This pattern is well-documented in Veeam exploitation toolkits. The account name `svc_backup_admin` is plausible as a legitimate service account, which is why the `SubjectUserName` (who did it) is more important than the `TargetUserName` (who was created) — see Q3. Trainees should also note the account was placed directly into the local Administrators group rather than Domain Admins, keeping the scope of compromise local to WIN-BACKUP1 initially.

---

### Q3. Who or what is shown as responsible for the action(s) in Question 2? Is this expected or suspicious?

**Answer:** The `SubjectUserName` in both the 4720 and 4732 events is **`VEEAMBACKUP$`** — the machine account for the Veeam Backup service host. This is **highly suspicious and never legitimate**. Machine accounts (identified by the trailing `$`) are used for computer-to-computer authentication and should never create human user accounts. This account appearing as the Subject is the direct fingerprint of CVE-2023-27532 exploitation: the attacker leveraged the Veeam service's own identity to make changes on the server.

**How to find it:**
```kql
winlog.event_id: (4720 or 4732) and host.name: "WIN-BACKUP1"
```
Expand either event and look at `winlog.event_data.SubjectUserName`. It will show `VEEAMBACKUP$`. Compare this to `winlog.event_data.SubjectDomainName` to confirm it is a machine account on this host (not a domain admin performing a legitimate task).

**Hint 1:** In the 4720 event from Q2, expand the `Subject` fields. Who does `SubjectUserName` show as the actor who created the account? Does it end with a `$` character?

**Hint 2:** Accounts ending in `$` are machine accounts. Under what normal circumstances would a machine account create a new local user? (Answer: none.)

**Trainer notes:** The `$` suffix convention for machine accounts is a critical piece of Windows authentication knowledge. Many trainees will not immediately recognise `VEEAMBACKUP$` as unusual — they may interpret it as a service account name rather than a machine account. Clarify: domain machine accounts take the form `HOSTNAME$` and are used exclusively for Kerberos computer authentication. They have no legitimate reason to call `NetUserAdd()` or `NetGroupAddUser()`. When a machine account appears as the Subject of account management events, it almost always means the service running as that account has been exploited or abused. This is one of the highest-fidelity IOCs in the entire scenario.

---

### Debrief

- CVE-2023-27532 (CVSS 7.5) was patched in March 2023; unpatched Veeam instances remain common in enterprise environments and are an attractive target because backup servers hold credentials for every system they protect.
- TCP 9401 reachable from a workstation is a segmentation failure — it should only be accessible from management subnets or the Veeam console host.
- A machine account (`HOSTNAME$`) appearing as the Subject of EID 4720/4732 is an extremely rare, high-fidelity IOC that should always generate an alert regardless of context.
- The 5-second gap between account creation and group addition is the signature of automation — human operators are never this fast.

---

## Hunt Task 4 — C2: Cloudflared Tunnel Detection

### Evidence Reference

| Time (UTC) | EID | Host | Detail |
|------------|-----|------|--------|
| 11:02:05 | Sysmon 11 | WIN-WS1 | `update.exe` dropped to `C:\ProgramData\Microsoft\Windows\` |
| 11:02:10 | 4688 + Sysmon 1 | WIN-WS1 | `sc create Wuauserv_Svc binPath= "...update.exe tunnel run --token..."` |
| 11:02:12 | 7045 | WIN-WS1 | Service `Wuauserv_Svc` installed — `ImagePath: ...update.exe` |
| 11:02:15 | 4688 | WIN-WS1 | `sc start Wuauserv_Svc` |
| 11:02:17 | Sysmon 1 | WIN-WS1 | `update.exe` spawned by `services.exe` — `OriginalFileName: cloudflared.exe` |
| 11:02:20–11:03:35 | Sysmon 3 ×5 | WIN-WS1 | TCP 443 → 198.41.192.227 (region2.v2.argotunnel.com) — all timed out |
| 11:03:50 | App EID 1 | WIN-WS1 | cloudflared: "failed to connect to edge: dial tcp … connection timed out" |

**MITRE:** T1572, T1543.003, T1036.004

---

### Q1. A new Windows service was installed. What is its name and what is the binary path? What is suspicious about this service compared to what it claims to be?

**Answer:**
- **Service name:** `Wuauserv_Svc`
- **Binary path:** `C:\ProgramData\Microsoft\Windows\update.exe tunnel run --token <redacted>`

Three things are suspicious:
1. The name `Wuauserv_Svc` closely mimics the legitimate Windows Update service (`wuauserv`) but adds a `_Svc` suffix — a name that does not exist on a stock Windows installation.
2. The binary path is in `C:\ProgramData\` — the legitimate Windows Update client is at `C:\Windows\System32\wuauclt.exe`. No legitimate Windows service lives in `ProgramData`.
3. The `ImagePath` includes `tunnel run --token` arguments — command-line arguments that belong to a tunnel proxy tool, not Windows Update.

**How to find it:**
```kql
winlog.event_id: 7045 and host.name: "WIN-WS1"
```
System EID 7045 fires every time a new service is registered. The key fields are `winlog.event_data.ServiceName` (the name), `winlog.event_data.ImagePath` (the full binary path including arguments), `winlog.event_data.ServiceType`, and `winlog.event_data.StartType`.

**Hint 1:** Search for System EID 7045 on WIN-WS1. What are the `ServiceName` and `ImagePath` values? Does the binary path look like the real Windows Update service?

**Hint 2:** Look up what `wuauserv` actually is on Windows and where its binary lives. Does the `ImagePath` in the 7045 event match?

**Trainer notes:** System EID 7045 is an underutilised but extremely powerful event — it fires for every service installation, including attacker-installed ones. The `ImagePath` field is particularly valuable because it includes the full command line with arguments, which often reveals the tool's true purpose (here: `tunnel run --token`). The `_Svc` suffix pattern is a common attacker naming convention to produce a near-match that passes a casual glance. Defenders should maintain a baseline inventory of all legitimate service names and binary paths; anything not on the baseline, especially with a `ProgramData` binary path, should alert immediately.

---

### Q2. What does the `OriginalFileName` field in Sysmon reveal about the binary?

**Answer:** The `OriginalFileName` field in the Sysmon EID 1 event for `update.exe` shows **`cloudflared.exe`**. This reveals that the binary on disk — despite being named `update.exe` — is actually the Cloudflare Tunnel client (`cloudflared`). The `OriginalFileName` is embedded in the PE (Portable Executable) file header at compile time and cannot be changed by simply renaming the file, making it one of the most reliable fields for identifying renamed binaries.

**How to find it:**
```kql
winlog.event_id: 1 and winlog.event_data.Image: *update.exe* and host.name: "WIN-WS1"
```
Expand the Sysmon EID 1 event for `update.exe` (spawned by `services.exe` at 11:02:17). Look for `winlog.event_data.OriginalFileName` in the event fields. It will show `cloudflared.exe` regardless of what the file was renamed to on disk.

**Hint 1:** Find the Sysmon EID 1 event for `update.exe` on WIN-WS1 (spawned by `services.exe`). Expand all fields and look for `OriginalFileName`. What does it say?

**Hint 2:** `OriginalFileName` comes from the PE header — a section of the binary's metadata baked in at compile time. A renamed file still has the same PE header. How does this help an analyst identify a disguised binary?

**Trainer notes:** `OriginalFileName` is extracted by Sysmon directly from the `VERSIONINFO` resource inside the PE file. It is set by the developer at compile time and cannot be altered by renaming or copying the file. This makes it one of the most reliable binary identification fields available — it survives file renaming, path changes, and even some packing methods. This is a critical detection concept: attackers routinely rename legitimate tools (cloudflared, ngrok, chisel) to blend with system processes. Without `OriginalFileName`, `update.exe` looks like a routine Windows binary; with it, the tool is immediately identified. Encourage trainees to always check this field when investigating suspicious executables, especially those with generic names in non-standard paths.

---

### Q3. Where did the binary attempt to connect? How many attempts were made?

**Answer:** The binary attempted to connect to **198.41.192.227** (which resolves to `region2.v2.argotunnel.com`) on **TCP port 443**. A total of **5 connection attempts** were made between 11:02:20 and 11:03:35 UTC — at approximately 20, 25, 35, 55, and 95 seconds after the service started, following an exponential backoff pattern.

**How to find it:**
```kql
winlog.event_id: 3 and winlog.event_data.Image: *update.exe* and host.name: "WIN-WS1"
```
Each Sysmon EID 3 event will show `destination.ip` = 198.41.192.227, `destination.port` = 443, and `winlog.event_data.DestinationHostname` = `region2.v2.argotunnel.com`. Counting the events and noting their timestamps reveals 5 attempts with increasing gaps.

**Hint 1:** Search for Sysmon EID 3 events where `Image` contains `update.exe`. How many events are there? What is the destination IP and hostname?

**Hint 2:** Look at the timestamps of all 5 events. What is the gap between the first and second attempt? Between the second and third? What pattern do you see?

**Trainer notes:** `argotunnel.com` is Cloudflare's proprietary tunnel infrastructure domain — it is not a generic CDN endpoint and its presence in outbound connection logs is a strong indicator of Cloudflare Tunnel usage. The exponential backoff (increasing gaps between retry attempts) is hardcoded in the cloudflared binary and is itself a behavioural fingerprint. The destination IP 198.41.192.227 falls within Cloudflare's IP range, which is why blocklisting individual IPs is ineffective — Cloudflare has thousands of edge IPs. The only reliable network-level countermeasure is egress filtering that blocks outbound connections to non-approved destinations on all ports, including 443 (which is why this attempt failed here).

---

### Q4. Was the connection successful? How can you tell from the logs?

**Answer:** **No — the C2 was not successfully established.** Two independent sources of evidence confirm failure:
1. All 5 Sysmon EID 3 connection events show outbound attempts with no corresponding inbound or successful state — all timed out.
2. Application log EID 1 at 11:03:50 UTC, attributed to the `cloudflared` provider, explicitly records the error: *"failed to connect to edge: dial tcp [198.41.192.227]:443: connection timed out"*.

**How to find it:**
```kql
winlog.channel: "Application" and winlog.event_id: 1 and host.name: "WIN-WS1"
```
The `winlog.event_data.Message` (or `message`) field contains the cloudflared error string. Cross-reference the timestamp (11:03:50) with the last Sysmon EID 3 event (~11:03:35) — the error fires shortly after the final retry exhausts.

**Hint 1:** After finding the 5 Sysmon EID 3 events, switch to the Application log: `winlog.channel: "Application"`. What EID 1 event appears just after the last connection attempt?

**Hint 2:** What does the `Message` field in that Application log event say? Does it confirm success or failure?

**Trainer notes:** This question teaches trainees to use multiple log sources together to reach a definitive conclusion. A Sysmon EID 3 event alone does not tell you whether a connection succeeded or failed — it records the attempt, not the outcome. The Application log event is the smoking gun: cloudflared writes its own error log via the Windows Event Log API when it fails, and the message is unambiguous. This is a useful general principle: when available, application-level events provide semantic context (success/failure/error reason) that network-level events like Sysmon 3 cannot. The fact that the C2 failed should also prompt a debrief discussion: what would the investigation have looked like if it had succeeded?

---

### Debrief

- Cloudflare Tunnel is increasingly used as a C2 transport: it uses TLS 443 (hard to block generically), targets Cloudflare infrastructure (hard to blocklist by IP), and the binary is legitimately signed. The only reliable countermeasure is allow-list-based egress filtering.
- `OriginalFileName` from Sysmon EID 1 is extracted from the PE header and cannot be changed by renaming — it is one of the most reliable fields for identifying renamed binaries and should be part of every process investigation.
- EID 7045 is a high-fidelity service installation event; the `ImagePath` field includes the full command line with arguments and should be checked against a baseline of known-good service binaries and paths.
- Service masquerading (T1036.004): defenders should maintain a service name and binary path inventory and alert on anything not matching a known-good baseline, especially binaries in `C:\ProgramData\`.

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
