"""Elasticsearch NDJSON bulk exporter.

Produces a single bulk_import.ndjson compatible with the Elasticsearch Bulk API:
  POST /<index>/_bulk
  Content-Type: application/x-ndjson

Each event becomes two lines:
  {"index": {"_index": "winlogbeat-artiforge-uc3-20260219_091200"}}
  { ...ECS-flavoured document... }
"""

from __future__ import annotations

import json
from pathlib import Path

from artiforge.core.models import ArtifactBundle, GeneratedEvent
from artiforge.mitre.technique_names import TECHNIQUE_NAMES

# Map ArtiForge channel names → ECS log.name values
_ECS_LOG_NAME = {
    "Security":    "Security",
    "System":      "System",
    "Sysmon":      "Microsoft-Windows-Sysmon/Operational",
    "Application": "Application",
    "PowerShell":  "Microsoft-Windows-PowerShell/Operational",
    "WMI":         "Microsoft-Windows-WMI-Activity/Operational",
}

_ECS_PROVIDER = {
    "Security":    "Microsoft-Windows-Security-Auditing",
    "System":      "Service Control Manager",
    "Sysmon":      "Microsoft-Windows-Sysmon",
    "Application": "Application",
    "PowerShell":  "Microsoft-Windows-PowerShell",
    "WMI":         "Microsoft-Windows-WMI-Activity",
}

_ECS_CATEGORY: dict[int, list[str]] = {
    # Authentication / Logon
    4624: ["authentication"], 4625: ["authentication"],
    4634: ["authentication"], 4648: ["authentication"],
    4672: ["authentication"], 4776: ["authentication"],
    # Kerberos
    4768: ["authentication"], 4769: ["authentication"], 4771: ["authentication"],
    # Process
    4688: ["process"],
    # Scheduled tasks
    4698: ["configuration"],
    # Account management
    4720: ["iam"], 4723: ["iam"], 4724: ["iam"],
    4725: ["iam"], 4726: ["iam"], 4732: ["iam"],
    # Object access / handles
    4656: ["file"], 4663: ["file"], 4670: ["file"],
    # Registry
    4657: ["registry"],
    # Windows Filtering Platform / Firewall
    5156: ["network"], 5157: ["network"],
    4946: ["configuration"], 4947: ["configuration"],
    # System
    7036: ["configuration"], 7045: ["configuration"],
    # Sysmon
    1:  ["process"],
    3:  ["network"],
    5:  ["process"],
    7:  ["file"],
    8:  ["process"],
    10: ["process"],
    11: ["file"],
    12: ["registry"],
    13: ["registry"],
    14: ["registry"],
    17: ["network"],
    18: ["network"],
    22: ["network"],
    23: ["file"],
    25: ["process"],
    # PowerShell
    4103: ["process"], 4104: ["process"],
    # WMI
    5857: ["configuration"], 5860: ["configuration"], 5861: ["configuration"],
}


def _to_ecs(ev: GeneratedEvent, include_meta: bool = True) -> dict:
    """Convert a GeneratedEvent to an ECS-compatible Winlogbeat document.

    When include_meta is True (default), lab-scoped metadata is emitted under
    the ECS-standard labels.* namespace so raw _source documents look like
    real Winlogbeat data. Set to False for max-realism scenarios where phase
    grading is done out-of-band.
    """
    doc: dict = {
        "@timestamp": ev.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "event": {
            "code": str(ev.eid),
            "provider": _ECS_PROVIDER.get(ev.channel, ev.channel),
            "kind": "event",
            "category": _ECS_CATEGORY.get(ev.eid, ["event"]),
            "outcome": "success",
            "module": "security" if ev.channel == "Security" else ev.channel.lower(),
        },
        "log": {
            "level": "information",
            "name": _ECS_LOG_NAME.get(ev.channel, ev.channel),
        },
        "host": {
            "name": ev.host,
            "hostname": ev.computer,
        },
        "winlog": {
            "record_id": ev.record_id,
            "channel": _ECS_LOG_NAME.get(ev.channel, ev.channel),
            "computer_name": ev.computer,
            "provider_name": ev.provider_name,
            "provider_guid": ev.provider_guid,
            "event_id": ev.eid,
            "event_data": ev.event_data,
        },
    }

    if include_meta:
        # ECS labels.* fields are all keyword-typed; phase_id must be a string
        # so ES maps it as keyword (not integer) under both the explicit
        # setup_index.sh template and fallback dynamic mapping.
        doc["labels"] = {
            "phase_id": str(ev.phase_id),
            "phase_name": ev.phase_name,
        }

    # Promote common fields to top level for easier hunting
    ed = ev.event_data
    if "CommandLine" in ed:
        doc["process"] = {
            "command_line": ed.get("CommandLine", ""),
            "name": (ed.get("NewProcessName", "") or ed.get("Image", "")).split("\\")[-1],
            "executable": ed.get("NewProcessName", "") or ed.get("Image", ""),
            "parent": {
                "executable": ed.get("ParentProcessName", "") or ed.get("ParentImage", ""),
            },
        }
    if "TargetUserName" in ed and ev.channel == "Security":
        doc["user"] = {
            "name": ed.get("TargetUserName", "") or ed.get("SubjectUserName", ""),
            "domain": ed.get("TargetDomainName", "") or ed.get("SubjectDomainName", ""),
        }
    if "DestinationIp" in ed:
        doc["destination"] = {
            "ip": ed.get("DestinationIp", ""),
            "port": int(ed.get("DestinationPort", 0)),
            "domain": ed.get("DestinationHostname", ""),
        }
        doc["source"] = {
            "ip": ed.get("SourceIp", ""),
            "port": int(ed.get("SourcePort", 0)),
        }
        doc["network"] = {
            "protocol": ed.get("Protocol", "tcp"),
            "direction": "egress",
        }

    # MITRE ATT&CK threat fields (ECS threat.* namespace)
    if ev.mitre_techniques:
        tids = ev.mitre_techniques
        doc["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": {
                "id":   tids,
                "name": [TECHNIQUE_NAMES.get(t, t) for t in tids],
            },
        }

    return doc


def export(bundle: ArtifactBundle, output_dir: Path, include_meta: bool = True) -> Path:
    """Write bulk_import.ndjson. Return the written path.

    Args:
        bundle: The artifact bundle to export.
        output_dir: Directory to write bulk_import.ndjson into.
        include_meta: When True (default), emit labels.phase_id and
            labels.phase_name on each document. Set to False to strip the
            labels block entirely (for max-realism scenarios).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    index_name = (
        f"winlogbeat-artiforge-{bundle.lab_id}"
        f"-{bundle.base_time.strftime('%Y%m%d_%H%M%S')}"
    )
    out_path = output_dir / "bulk_import.ndjson"

    lines: list[str] = []
    for ev in sorted(bundle.events, key=lambda e: e.timestamp):
        action = json.dumps({"index": {"_index": index_name}})
        doc = json.dumps(_to_ecs(ev, include_meta=include_meta))
        lines.append(action)
        lines.append(doc)

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path
