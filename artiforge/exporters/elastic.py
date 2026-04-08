"""Elasticsearch NDJSON bulk exporter.

Produces a single bulk_import.ndjson compatible with the Elasticsearch Bulk API:
  POST /<index>/_bulk
  Content-Type: application/x-ndjson

Each event becomes two lines:
  {"index": {"_index": "winlogbeat-artiforge-uc3"}}
  { ...ECS-flavoured document... }
"""

from __future__ import annotations

import json
from pathlib import Path

from artiforge.core.models import ArtifactBundle, GeneratedEvent

# Map ArtiForge channel names → ECS log.name values
_ECS_LOG_NAME = {
    "Security":    "Security",
    "System":      "System",
    "Sysmon":      "Microsoft-Windows-Sysmon/Operational",
    "Application": "Application",
}

_ECS_PROVIDER = {
    "Security":    "Microsoft-Windows-Security-Auditing",
    "System":      "Service Control Manager",
    "Sysmon":      "Microsoft-Windows-Sysmon",
    "Application": "Application",
}

_ECS_CATEGORY: dict[int, list[str]] = {
    4624: ["authentication"], 4625: ["authentication"],
    4634: ["authentication"], 4648: ["authentication"],
    4672: ["authentication"], 4688: ["process"],
    4698: ["configuration"],
    4720: ["iam"],            4732: ["iam"],
    7045: ["configuration"],
    1:    ["process"],
    3:    ["network"],
    11:   ["file"],
    13:   ["registry"],
}


def _to_ecs(ev: GeneratedEvent) -> dict:
    """Convert a GeneratedEvent to an ECS-compatible Winlogbeat document."""
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
        "artiforge": {
            "phase_id": ev.phase_id,
            "phase_name": ev.phase_name,
        },
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

    return doc


def export(bundle: ArtifactBundle, output_dir: Path) -> Path:
    """Write bulk_import.ndjson. Return the written path."""
    output_dir.mkdir(parents=True, exist_ok=True)

    index_name = f"winlogbeat-artiforge-{bundle.lab_id}"
    out_path = output_dir / "bulk_import.ndjson"

    lines: list[str] = []
    for ev in sorted(bundle.events, key=lambda e: e.timestamp):
        action = json.dumps({"index": {"_index": index_name}})
        doc = json.dumps(_to_ecs(ev))
        lines.append(action)
        lines.append(doc)

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path
