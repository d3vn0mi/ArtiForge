# UC3 "Egg-Cellent Resume" — Trainee Brief

**Difficulty:** Intermediate  
**Estimated time:** 90 minutes  
**Tools:** Kibana, KQL

---

## Scenario Briefing

Your organisation received a tip from HR: an employee named **marcus.webb** opened an
unusual file attachment — described as a CV sent by email — on his workstation
(**WIN-WS1**) on the morning of **19 February 2026**. Shortly afterwards, a colleague
noticed unexpected network activity involving several internal servers.

You have been tasked with investigating. Windows event logs have been collected and
loaded into Kibana. Your job is to trace what happened, step by step, from the moment
the file was opened through to the final activity observed on the network.

There is no malware sample to analyse. Work from the logs alone.

---

## Your Role

You are a **Tier-2 SOC analyst** performing an initial investigation. You will need to:

- Reconstruct the attacker's actions from Windows event data
- Identify the techniques used at each stage
- Document your findings with supporting evidence (timestamps, event IDs, field values)

---

## Environment Access

| Item | Value |
|------|-------|
| Kibana URL | `http://localhost:5601` |
| Index pattern | `winlogbeat-artiforge-uc3` |
| Time filter start | `2026-02-19 09:00:00 UTC` |
| Time filter end | `2026-02-19 11:30:00 UTC` |
| Known victim user | `marcus.webb` (domain: `LAB`) |
| Known victim host | `WIN-WS1` (10.10.10.10) |

**Tip:** Set the Kibana time filter first. All events fall within the window above.

---

## Event ID Reference

| Event ID | Channel | Description |
|----------|---------|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4634 | Security | Logoff |
| 4648 | Security | Logon with explicit credentials |
| 4672 | Security | Special privileges assigned to logon |
| 4688 | Security | Process created |
| 4698 | Security | Scheduled task created |
| 4720 | Security | User account created |
| 4732 | Security | Member added to security group |
| 7045 | System | New service installed |
| Sysmon 1 | Sysmon | Process created (with hashes + full parent chain) |
| Sysmon 3 | Sysmon | Network connection |
| Sysmon 11 | Sysmon | File created |
| Sysmon 13 | Sysmon | Registry value set |
| App EID 1 | Application | Application log entry |

---

## Useful KQL Patterns

```kql
# Filter by host
host.name: "WIN-WS1"

# Filter by event ID
winlog.event_id: 4688

# Filter by process command line
process.command_line: *keyword*

# Filter by user
user.name: "marcus.webb"

# Filter by destination IP or port
destination.ip: "10.10.10.20"
destination.port: 443

# Filter by ECS category
event.category: "process"
```

---

## Hunt Tasks

Complete each task in order. Document your answers with supporting evidence.

---

### Task 1 — Initial Execution

**Background:** The incident started with marcus.webb opening a file on WIN-WS1.

**Questions:**
1. What process first executed as a result of the file being opened? What was its
   full command line, and what spawned it?
2. A chain of processes followed. List every process in the chain from first to last,
   including the parent-child relationships.
3. What files were written to disk in the minutes immediately before or during
   this execution? Where were they written?

**Submit:** A process tree showing each hop, with timestamps and command lines.

---

### Task 2 — Persistence

**Background:** After initial execution, the attacker established a foothold to survive
a reboot.

**Questions:**
1. What persistence mechanism was created, and what is its name?
2. How was it created? What command was run, and what is unusual about the method used?
3. Where is the configuration for this mechanism stored on disk?
   What is unusual about the file extension?

**Submit:** The persistence mechanism name, the command used to create it, and the
path of any associated files.

---

### Task 3 — Pivot to Internal Server

**Background:** Approximately 60 minutes after initial access, the attacker turned their
attention to another internal host.

**Questions:**
1. Which internal host did the attacker connect to from WIN-WS1, and on which port?
   What service or software typically listens on this port?
2. What happened on that internal host as a result? Identify the specific event(s)
   and their details.
3. Who or what is shown as responsible for the action(s) in Question 2?
   Is this expected or suspicious?

**Submit:** Destination host and port, the resulting event IDs with details, and an
assessment of whether the actor shown in the logs is legitimate.

---

### Task 4 — Command and Control Attempt

**Background:** The attacker attempted to establish an outbound communication channel
from WIN-WS1.

**Questions:**
1. A new Windows service was installed. What is its name and what is the binary path?
   What is suspicious about this service compared to what it claims to be?
2. What does the `OriginalFileName` field in Sysmon reveal about the binary?
3. Where did the binary attempt to connect? How many attempts were made?
4. Was the connection successful? How can you tell from the logs?

**Submit:** Service name, binary path, true binary identity, connection destination,
attempt count, and outcome (success/failure with evidence).

---

### Task 5 — Lateral Movement and Collection

**Background:** Approximately 2 hours after initial access, the attacker moved to
another host.

**Questions:**
1. Which host did the attacker move to, and how (what protocol / method)?
   What was the source IP?
2. What credential was used to authenticate? Where have you seen this credential
   before in this investigation?
3. What did the attacker do after gaining access to the new host?
   Identify the command run and any resulting file artefacts.
4. Was any data successfully exfiltrated? What evidence supports your conclusion?

**Submit:** Destination host, lateral movement method, credential used with its origin,
post-compromise activity, and exfiltration assessment.

---

## Submission Format

For each task, provide:

```
Task N
-------
Finding: [Your answer in 1-3 sentences]
Evidence:
  - Timestamp: YYYY-MM-DDTHH:MM:SSZ
  - Event ID: XXXX
  - Host: WIN-XXX
  - Key field: value
  - Key field: value
MITRE technique: TXXXX.XXX (if you can identify it)
```

---

## Notes

- Not every host generates events in every phase — absence of logs from a host is
  itself an observation worth noting
- The same credential may appear across multiple phases — track accounts throughout
  the timeline
- Sysmon EID 1 gives richer process information (hashes, full parent chain) than
  Security EID 4688 — use both
- If you are completely stuck on a task, move to the next and return later
