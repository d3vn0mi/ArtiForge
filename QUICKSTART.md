# ArtiForge — Quick Start Guide

End-to-end walkthrough: spin up a local Elastic stack, generate UC3 artifacts,
ingest them, and hunt through the events in Kibana.

---

## Prerequisites

| Tool | Min version | Check |
|------|------------|-------|
| Python | 3.10+ | `python --version` |
| Docker | 24+ | `docker --version` |
| Docker Compose | v2 | `docker compose version` |
| curl | any | `curl --version` |

> **RAM:** Elasticsearch needs at least **2 GB free** for the single-node container.

---

## Step 1 — Install ArtiForge

```bash
git clone <repo-url>
cd ArtiForge

pip install -r requirements.txt
```

Verify the install:

```bash
python cli.py list-labs
```

Expected output:
```
ID           NAME                           PHASES  EVENTS   DESCRIPTION
────────────────────────────────────────────────────────────────────────────────
  uc3        Egg-Cellent Resume                  5      37   LOLBAS execution chain...
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

Generate all 37 events and 5 file stubs for the UC3 scenario:

```bash
python cli.py generate --lab uc3 --output ./artifacts
```

Output:
```
[ArtiForge] Generating artifacts for lab: Egg-Cellent Resume
  [xml]     → artifacts/uc3_20260219_091200/events  (7 files)
  [elastic] → artifacts/uc3_20260219_091200/elastic/bulk_import.ndjson
  [files]   → artifacts/uc3_20260219_091200/files  (5 artifacts)

  Summary: 37 events generated
  Output:  /path/to/ArtiForge/artifacts/uc3_20260219_091200
```

**Options:**

```bash
# Use a specific timestamp (useful for repeatable demos)
python cli.py generate --lab uc3 --base-time "2026-02-19T09:12:00Z"

# Generate only selected phases
python cli.py generate --lab uc3 --phases 1,4

# XML only (skip Elastic NDJSON)
python cli.py generate --lab uc3 --format xml
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
    Index : winlogbeat-artiforge-uc3
    ES    : http://localhost:9200

--> Checking Elasticsearch... ready.
--> Ingesting 37 documents...
    Indexed : 37
    Errors  : none
--> Verified: 37 documents in index 'winlogbeat-artiforge-uc3'

==> Ingest complete.
```

**One-shot alternative** (generate + ingest in a single command):

```bash
bash scripts/run_lab.sh uc3
```

---

## Step 6 — Explore in Kibana

Open **http://localhost:5601** in your browser.

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

See all 37 events in attack order across all hosts:

```kql
artiforge.phase_id : *
```

Add these columns in Discover for a clean timeline:
- `@timestamp`
- `host.name`
- `winlog.event_id`
- `winlog.channel`
- `artiforge.phase_name`
- `process.command_line`

Sort by `@timestamp` ascending.

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
