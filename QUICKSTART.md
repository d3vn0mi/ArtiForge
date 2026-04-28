# ArtiForge — Quick Start Guide

End-to-end walkthrough: spin up a local Elastic stack, generate UC3 artifacts,
ingest them, and hunt through the events in Kibana.

---

## Prerequisites

| Tool | Min version | Check |
|------|------------|-------|
| Docker | 24+ | `docker --version` |
| Docker Compose | v2 | `docker compose version` |
| curl | any | `curl --version` |

> **RAM:** Elasticsearch needs at least **2 GB free** for the single-node container.

> **Python not required.** ArtiForge runs inside Docker — no local Python install needed.

---

## Local vs. Remote Server

| Scenario | Kibana URL | Run scripts from |
|----------|-----------|-----------------|
| Laptop (local) | `http://localhost:5601` | same machine |
| Remote/cloud VM | `http://<PUBLIC_IP>:5601` | SSH into the server |

**Port exposure:**
- **Kibana (5601)** is accessible on the public IP — open this in your browser.
- **Elasticsearch (9200)** is bound to `127.0.0.1` only. It is **not** reachable from outside the server. The ingest scripts run on the server itself, so `localhost:9200` works for them. This prevents unauthenticated public access to your event data.

**Firewall rule (cloud VMs):** open TCP 5601 inbound in your security group / firewall.

```bash
# AWS example
aws ec2 authorize-security-group-ingress --group-id sg-xxx \
  --protocol tcp --port 5601 --cidr 0.0.0.0/0

# ufw example
sudo ufw allow 5601/tcp
```

---

## Step 1 — Build the ArtiForge Image

```bash
git clone <repo-url>
cd ArtiForge

docker build -t artiforge:latest .
```

Verify the image works:

```bash
./artiforge.sh list-labs
```

Expected output:
```
ID           NAME                           PHASES  EVENTS   DESCRIPTION
────────────────────────────────────────────────────────────────────────────────
  uc3        Egg-Cellent Resume                  5      40   LOLBAS execution chain...
  uc3n       Egg-Cellent Resume (Noisy)          5      40   Same attack as UC3 with...
```

---

## Step 2 — Start the Lab Environment

```bash
docker compose up -d
```

This starts:
- **Elasticsearch** on `http://localhost:9200` — event store
- **Kibana** on `http://localhost:5601` — hunting UI

Check both containers are healthy (takes ~60 s on first run):

```bash
docker compose ps
```

Wait until both show `healthy`:
```
NAME                STATUS
artiforge-es        running (healthy)
artiforge-kibana    running (healthy)
```

Confirm Elasticsearch is up:
```bash
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
```

---

## Step 3 — Set Up the Index Template

Run once before the first ingest to create the Elasticsearch index mapping
and the Kibana data view:

```bash
bash scripts/setup_index.sh
```

Expected output:
```
==> ArtiForge — Index Setup
--> Waiting for Elasticsearch... ready.
--> Installing index template 'artiforge'...   OK
--> Waiting for Kibana... ready.
--> Creating Kibana data view 'winlogbeat-artiforge-*'...   OK  id=...

==> Setup complete.
```

---

## Step 4 — Generate Artifacts

Generate all 40 events and 5 file stubs for the UC3 scenario:

```bash
./artiforge.sh generate --lab uc3 --output /work/artifacts
```

Output:
```
[ArtiForge] Generating artifacts for lab: Egg-Cellent Resume
  [xml]     → artifacts/uc3_20260219_091200/events  (7 files)
  [elastic] → artifacts/uc3_20260219_091200/elastic/bulk_import.ndjson
  [files]   → artifacts/uc3_20260219_091200/files  (5 artifacts)

  Summary: 40 events generated
  Output:  /path/to/ArtiForge/artifacts/uc3_20260219_091200
```

**Options:**

```bash
# Use a specific timestamp (useful for repeatable demos)
./artiforge.sh generate --lab uc3 --base-time "2026-02-19T09:12:00Z"

# Generate only selected phases
./artiforge.sh generate --lab uc3 --phases 1,4

# XML only (skip Elastic NDJSON)
./artiforge.sh generate --lab uc3 --format xml

# Preview without writing files
./artiforge.sh generate --lab uc3 --dry-run
```

---

## Step 5 — Ingest into Elasticsearch

```bash
bash scripts/ingest.sh artifacts/uc3_*/elastic/bulk_import.ndjson
```

Expected output:
```
==> ArtiForge — Ingest
    File  : artifacts/uc3_.../elastic/bulk_import.ndjson
    Index : winlogbeat-artiforge-uc3-20260219_091200
    ES    : http://localhost:9200

--> Checking Elasticsearch... ready.
--> Ingesting 40 documents...
    Indexed : 40
    Errors  : none
--> Verified: 40 documents in index 'winlogbeat-artiforge-uc3-20260219_091200'

==> Ingest complete.
```

**One-shot alternative** (generate + ingest in a single command):

```bash
bash scripts/run_lab.sh uc3
```

---

## Step 6 — Explore in Kibana

Open Kibana in your browser:
- **Local:** `http://localhost:5601`
- **Remote server:** `http://<PUBLIC_IP>:5601`

Navigate to **Discover** (left sidebar → magnifying glass icon).

Change the data view (top-left dropdown) to **ArtiForge Labs**.

Set the time range to cover the scenario: **Feb 19 2026, 09:00 → 12:00**
(or use the absolute range picker and enter the base time + 3 hours).

---

## Kibana Queries — Hunt Task Walkthrough

Below are KQL queries that map directly to the UC3 student hunt tasks.
Paste them into the **search bar** in Discover.

---

### Hunt Task 01 — Find the LOLBAS Chain

**Goal:** Reconstruct the `ie4uinit → msxsl → cmd` process tree.

```kql
winlog.event_id : (4688 or 1) and host.name : "WIN-WS1"
```

Sort by `@timestamp` ascending. Look for this chain in `process.command_line`:

| # | Process | Parent | Key signal |
|---|---------|--------|------------|
| 1 | `ie4uinit.exe -BaseSettings` | `explorer.exe` | LOLBIN triggered by LNK |
| 2 | `msxsl.exe … style.xsl` | `ie4uinit.exe` | LOLBIN → XSL execution |
| 3 | `cmd.exe /c whoami && net user` | `msxsl.exe` | First-stage enumeration |

To focus on just the chain:
```kql
process.command_line : ("ie4uinit" or "msxsl" or "whoami") and host.name : "WIN-WS1"
```

---

### Hunt Task 02 — Persistence: Scheduled Task

**Goal:** Find the scheduled task created via a disguised XML file.

```kql
winlog.event_id : 4698 and host.name : "WIN-WS1"
```

Expand the event. Check `winlog.event_data.TaskName` — it mimics a legitimate
Edge updater task. Then find the file write that preceded it:

```kql
winlog.event_id : 11 and winlog.event_data.TargetFilename : "*update.txt*"
```

Also check the schtasks command line:
```kql
process.command_line : "/XML" and host.name : "WIN-WS1"
```

Key finding: `schtasks /Create /TN "MicrosoftEdgeUpdateTaskMachineUA" /XML … update.txt /F`
The file has a `.txt` extension but contains valid XML task definition.

---

### Hunt Task 03 — Detect Cloudflared Service

**Goal:** Find the masqueraded binary and its repeated failed egress attempts.

Find the service install:
```kql
winlog.event_id : 7045 and host.name : "WIN-WS1"
```

Expand the event. Check:
- `winlog.event_data.ServiceName` = `Wuauserv_Svc` (spoofed Windows Update name)
- `winlog.event_data.ImagePath` contains `update.exe` in `C:\ProgramData\` (non-standard path)

Find the failed connection attempts:
```kql
winlog.event_id : 3 and destination.ip : "198.41.192.227"
```

You should see **5 identical events** to `region2.v2.argotunnel.com:443` — all
from `C:\ProgramData\Microsoft\Windows\update.exe`.

Check the Application log error:
```kql
winlog.channel : "Application" and winlog.event_id : 1
```

---

### Hunt Task 04 — Trace the Veeam Pivot

**Goal:** Link WS1 → BACKUP1 via TCP 9401, account creation, and explicit credentials.

Find the network connection to Veeam port:
```kql
winlog.event_id : 3 and destination.port : 9401
```

Find the new account on BACKUP1:
```kql
winlog.event_id : (4720 or 4732) and host.name : "WIN-BACKUP1"
```

Find the explicit credential use from WS1:
```kql
winlog.event_id : 4648 and host.name : "WIN-BACKUP1"
```

Expand the 4648 event. Confirm:
- `winlog.event_data.IpAddress` = `10.10.10.10` (WIN-WS1)
- `winlog.event_data.TargetUserName` = `svc_backup_admin`
- Timestamp is within seconds of the 4720/4732 events

---

### Hunt Task 05 — Lateral Movement: RDP to WIN-WS2

**Goal:** Map the full lateral path and identify staged files.

Find the RDP logon:
```kql
winlog.event_id : 4624 and host.name : "WIN-WS2"
```

Expand the event. Confirm:
- `winlog.event_data.LogonType` = `10` (RemoteInteractive / RDP)
- `winlog.event_data.IpAddress` = `10.10.10.10`
- `winlog.event_data.TargetUserName` = `svc_backup_admin`

Find the staged ZIP file:
```kql
winlog.event_id : 11 and host.name : "WIN-WS2"
```

Find the Compress-Archive command:
```kql
process.command_line : "Compress-Archive" and host.name : "WIN-WS2"
```

---

### Full Timeline View — All Phases

See all 40 events in attack order across all hosts:

```kql
labels.phase_id : *
```

To filter out noise events (UC3N):

```kql
NOT labels.phase_name : "noise"
```

Add these columns in Discover for a clean timeline:
- `@timestamp`
- `host.name`
- `winlog.event_id`
- `winlog.channel`
- `labels.phase_name`
- `process.command_line`

Sort by `@timestamp` ascending.

> **Note:** Lab-scoped metadata lives under the ECS-standard `labels.*` namespace
> (was `artiforge.*` prior to v0.6). To generate events with no labels block at
> all — for a max-realism scenario where phase grading is done out-of-band — use
> `artiforge generate --lab uc3 --no-meta`.

---

## Upgrading from v0.5

ArtiForge v0.6 moved lab-scoped metadata from the `artiforge.*` namespace to
the ECS-standard `labels.*` namespace (`labels.phase_id`, `labels.phase_name`).
This is a breaking change for Kibana state created under v0.5. Follow these
steps before re-ingesting with v0.6:

```bash
# 1. Delete any indices created under the v0.5 template.
#    (Old indices have artiforge.phase_id mapped as integer — that mapping
#    is immutable, so new labels.* writes get inconsistent dynamic mapping.)
curl -X DELETE "http://localhost:9200/winlogbeat-artiforge-*"

# 2. Delete the existing "ArtiForge Labs" data view in Kibana.
#    Stack Management -> Data Views -> ArtiForge Labs -> trash icon.
#    (The v0.5 data view has a sourceFilter hiding the artiforge.* namespace
#    that no longer exists, and re-running setup_index.sh will not update it.)

# 3. Re-run the setup script and ingest as normal.
bash scripts/setup_index.sh
bash scripts/run_lab.sh uc3
```

If you have saved Kibana searches or dashboards that reference
`artiforge.phase_id` / `artiforge.phase_name`, update them to use
`labels.phase_id` / `labels.phase_name`.

### `--no-meta` and noisy labs

`artiforge generate --no-meta` strips the entire `labels.*` block from the
NDJSON output. Do **not** use it with labs that have a `noise:` section
(currently **UC3N**) — the trainee brief's `NOT labels.phase_name : "noise"`
query will silently match nothing. `--no-meta` is intended for max-realism
scenarios where phase grading happens out-of-band. ArtiForge will emit a
warning if you combine `--no-meta` with a noise-enabled lab.

---

## Tear Down

```bash
docker compose down          # stop containers, keep data volume
docker compose down -v       # stop containers AND delete all data
```

To re-ingest fresh artifacts after a `down -v`:

```bash
bash scripts/setup_index.sh
bash scripts/run_lab.sh uc3
```

---

## Realistic Hunt Exercise — UC3E with Max Noise, No Metadata

This section walks through a **production-grade hunt exercise**: generate the
UC3E scenario with the `--no-meta` flag (strips all ArtiForge training
metadata from the NDJSON), so the events in Kibana look exactly like real
Winlogbeat data. Trainees see hundreds of events with no `labels.phase_id`
to lean on — they must hunt through genuine-looking noise to find the attack.

### Generate with --no-meta

```bash
./artiforge.sh generate --lab uc3e --format elastic --no-meta --seed 42 \
  --output /work/artifacts
```

> **What `--no-meta` does:** Removes the `labels.phase_id` and
> `labels.phase_name` fields from every event. Trainees cannot filter by
> phase or distinguish attack from noise using metadata — they must rely on
> event content, timestamps, and forensic reasoning.

Expected output:
```
[ArtiForge] Generating artifacts for lab: Egg-Cellent Resume (Enhanced)
  [elastic] → artifacts/uc3e_20260219_091200/elastic/bulk_import.ndjson (no labels)

  Summary: 278 events generated
```

The NDJSON contains **~278 events** — 44 attack events buried in ~234 noise
events from the `office_hours` and `24x7_server` temporal profiles. All events
look identical in structure — no training labels to give away which are real.

### Ingest into Elasticsearch

```bash
# Make sure the lab environment is running
docker compose up -d

# Wait for healthy status
docker compose ps

# Set up the index template (only needed once)
bash scripts/setup_index.sh

# Ingest the no-meta events
bash scripts/ingest.sh artifacts/uc3e_*/elastic/bulk_import.ndjson
```

Expected output:
```
==> ArtiForge — Ingest
    File  : artifacts/uc3e_.../elastic/bulk_import.ndjson
    Index : winlogbeat-artiforge-uc3e-20260219_091200
    ...
--> Verified: 278 documents in index
```

### Verify in Kibana

Open Kibana at `http://localhost:5601` (or `http://<SERVER_IP>:5601`).

1. Go to **Discover** (left sidebar → magnifying glass)
2. Select the **ArtiForge Labs** data view (top-left dropdown)
3. Set time range to **Feb 19 2026, 09:00 → 12:00**

You should see **278 events**. Confirm there is no `labels.phase_id` column
available — this verifies `--no-meta` is working.

### Verify the noise is realistic

Run these queries to confirm the mix of attack and noise events looks
authentic:

**Check total event count by host:**
```kql
host.name : *
```
Add `host.name` as a column. You should see events spread across WIN-WS1,
WIN-WS2, WIN-DC1, and WIN-BACKUP1 — the noise profiles create activity on
every host.

**Check process execution events (attack + noise mixed together):**
```kql
winlog.event_id : 1 and winlog.channel : "Microsoft-Windows-Sysmon/Operational"
```
You should see a mix of benign processes (chrome.exe, svchost.exe,
RuntimeBroker.exe) alongside the attack processes (ie4uinit.exe, msxsl.exe).
The trainee's job is to spot the malicious ones.

**Check DNS queries (attack + noise mixed):**
```kql
winlog.event_id : 22
```
Benign domains (google.com, microsoft.com) are mixed with the suspicious
`argotunnel.com` queries. Trainees must identify which DNS lookups are C2.

**Check network connections (attack + noise mixed):**
```kql
winlog.event_id : 3
```
Normal HTTPS connections to Microsoft/Google CDNs alongside the Cloudflared
tunnel attempts to `198.41.192.227:443` and the Veeam connection to port 9401.

**Check logon events (noise-heavy on DC):**
```kql
winlog.event_id : 4624
```
WIN-DC1 should have heavy logon traffic (the `24x7_server` profile generates
many logon pairs). The real attack logons on WIN-WS1 and WIN-WS2 are buried
in this noise.

### Validate the attack is still findable

Even without metadata labels, a skilled analyst should be able to find the
attack chain. Run the ArtiForge detection check to confirm the attack events
are present and detectable:

```bash
./artiforge.sh check --lab uc3e --seed 42
```

Expected output:
```
[ArtiForge] Checking lab: Egg-Cellent Resume (Enhanced)
  44 attack events  ·  278 total

  Built-in rules:
  FIRED  DR-001  Suspicious LOLBin Execution    T1218      (3 events)
  FIRED  DR-002  Scheduled Task Creation        T1053.005  (1 event)
  FIRED  DR-003  Service Installation           T1543.003  (1 event)
  ...
  Coverage: 10/13 rules fired (76.9%)

  Sigma rules:
  FIRED  [sigma]  LOLBin Process Creation       T1218      (2 events)
  FIRED  [sigma]  Cloudflared Tunnel Connection T1090      (5 events)
  ...
  Coverage: 4/5 rules fired (80.0%)
```

This confirms the attack events are embedded in the data and detectable with
both built-in and Sigma rules — the trainee just needs to find them without
the training labels.

### Suggested hunt approach for trainees

Give trainees these instructions (no answers):

> You have received a Winlogbeat data export from a Windows domain with 4
> hosts. Intelligence suggests an attacker may have compromised the network
> via a phishing lure. Your task:
>
> 1. Identify the initial access vector and the compromised user
> 2. Map the full attack chain across all hosts
> 3. Identify any persistence mechanisms
> 4. Find evidence of lateral movement
> 5. Determine what data (if any) was staged for exfiltration
>
> Start by looking at process creation events on the workstation hosts
> and work outward from there.

---

## Reference — Event ID Cheat Sheet

| EID | Channel | Phase | What to look for |
|-----|---------|-------|-----------------|
| 4688 | Security | 1,2,3,4,5 | CommandLine field — the full LOLBAS chain |
| 4698 | Security | 2 | TaskName mimics Edge updater |
| 4720 | Security | 3 | New account `svc_backup_admin` on BACKUP1 |
| 4732 | Security | 3 | Account added to Administrators on BACKUP1 |
| 4648 | Security | 3,5 | Explicit creds from WS1 IP |
| 7045 | System | 4 | Service install — binary path in `C:\ProgramData\` |
| 4624 | Security | 5 | LogonType=10 (RDP) on WIN-WS2 |
| 4634 | Security | 5 | Session ended on WIN-WS2 |
| Sysmon 1 | Sysmon | 1–5 | Parent/child process tree + hashes |
| Sysmon 3 | Sysmon | 3,4 | Network connections (TCP 9401, TCP 443 to Cloudflare) |
| Sysmon 11 | Sysmon | 1,2,4,5 | File drops (INF, XSL, update.exe, update.txt, ZIP) |
| Sysmon 13 | Sysmon | 2 | Registry key written for scheduled task |
| App 1 | Application | 4 | Cloudflared error after all tunnel retries failed |
