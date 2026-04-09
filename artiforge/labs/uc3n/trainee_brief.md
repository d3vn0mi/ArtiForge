# UC3-N "Egg-Cellent Resume" — Noisy Edition — Trainee Brief

**Difficulty:** Intermediate–Advanced  
**Estimated time:** 120 minutes  
**Tools:** Kibana, KQL  
**Based on:** UC3 (same attack, realistic background noise added)

---

## What is Different From UC3

This lab uses the **identical attack chain** as UC3. The difference is that all
four hosts are now generating realistic background traffic throughout the
scenario window:

| Host | Noise type | Volume |
|------|-----------|--------|
| WIN-WS1 | Logon pairs, process spawns (Chrome, Office, svchost), DNS queries | High |
| WIN-DC1 | Logon pairs (domain auth traffic) | Very high — DC sees all domain logons |
| WIN-WS2 | Logon pairs, process spawns, DNS queries | Medium (quiet before attacker arrives) |
| WIN-BACKUP1 | Logon pairs, process spawns | Low |

All noise events carry `artiforge.phase_name: "noise"` in Kibana.

**Before you start hunting, try both of these queries:**

```kql
# Full dataset — everything including noise
artiforge.phase_id : *

# Attack events only — use this to check your answers
NOT artiforge.phase_name : "noise"
```

Your goal is to find the attack without using the second filter — that is, to
identify the malicious events from the noise the same way a real analyst would.

---

## Scenario Briefing

*(Identical to UC3 — reproduced here for convenience.)*

Your organisation received a tip from HR: an employee named **marcus.webb** opened an
unusual file attachment — described as a CV sent by email — on his workstation
(**WIN-WS1**) on the morning of **19 February 2026**. Shortly afterwards, a colleague
noticed unexpected network activity involving several internal servers.

You have been tasked with investigating. Windows event logs have been collected and
loaded into Kibana. Your job is to trace what happened, step by step, from the moment
the file was opened through to the final activity observed on the network.

---

## Environment Access

| Item | Value |
|------|-------|
| Kibana URL | `http://localhost:5601` |
| Index pattern | `winlogbeat-artiforge-uc3n-*` |
| Time filter start | `2026-02-19 09:00:00 UTC` |
| Time filter end | `2026-02-19 11:30:00 UTC` |
| Known victim user | `marcus.webb` (domain: `LAB`) |
| Known victim host | `WIN-WS1` (10.10.10.10) |

---

## Noise-Aware Hunting Tips

1. **Filter by user first** — noise events use the host's first user account.
   Unusual parent–child process relationships (explorer → ie4uinit) stand out
   even in a noisy process list.

2. **Rare process names** — `msxsl.exe`, `ie4uinit.exe`, `schtasks.exe /XML`,
   and `sc.exe` with `binPath=` are uncommon regardless of noise volume.

3. **Cross-host pivots** — noise stays on its own host. A Sysmon 3 connection
   from WIN-WS1 to port 9401 on WIN-BACKUP1 has no noise equivalent.

4. **Destination IP / port anomalies** — filter on `destination.port : 9401`
   or `destination.ip : "198.41.192.227"` to cut through all background DNS
   and process events instantly.

5. **WIN-DC1 is a red herring** — it generates logon noise but plays no role
   in the attack. If you see activity there, rule it out before digging deeper.

---

## Hunt Tasks

The five tasks are identical to UC3. Refer to the UC3 trainee brief for the
full question list. The only difference is that you must now isolate each
finding from the surrounding noise.

---

## Submission Format

```
Task N
-------
Finding: [Your answer in 1-3 sentences]
Evidence:
  - Timestamp: YYYY-MM-DDTHH:MM:SSZ
  - Event ID: XXXX
  - Host: WIN-XXX
  - Key field: value
KQL used: [the query that surfaced this event]
MITRE technique: TXXXX.XXX
```

---

## Notes

- Attack event timestamps have **±2–15 second jitter** depending on the phase —
  they will not fall on perfectly round-numbered seconds.
- The Sysmon 3 connection attempts in Phase 4 have **variable gaps** (not uniform
  backoff) — this is intentional and realistic.
- WIN-DC1 has no attack events — all activity there is noise.
- Generate with `--seed 1337` for a reproducible dataset, or omit `--seed` for a
  fresh random run each time.
