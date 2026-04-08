"""Windows Event Log XML exporter.

Produces one XML file per (host, channel) pair.
The XML format matches Windows Event Viewer / wevtutil export schema.
"""

from __future__ import annotations

import xml.dom.minidom
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

from artiforge.core.models import ArtifactBundle, GeneratedEvent
from artiforge.core.timeline import format_system_time

# Channel name → XML channel path
_CHANNEL_PATH = {
    "Security":    "Security",
    "System":      "System",
    "Sysmon":      "Microsoft-Windows-Sysmon/Operational",
    "Application": "Application",
}

# Channel → Keywords value
_KEYWORDS = {
    "Security": "0x8020000000000000",
    "System":   "0x8000000000000000",
    "Sysmon":   "0x8000000000000000",
    "Application": "0x80000000000000",
}


def _build_event_element(ev: GeneratedEvent) -> ET.Element:
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    event = ET.Element("Event", xmlns=ns)

    # System
    system = ET.SubElement(event, "System")

    provider = ET.SubElement(system, "Provider")
    provider.set("Name", ev.provider_name)
    provider.set("Guid", ev.provider_guid)

    ET.SubElement(system, "EventID").text = str(ev.eid)
    ET.SubElement(system, "Version").text = "0"
    ET.SubElement(system, "Level").text = str(ev.level)
    ET.SubElement(system, "Task").text = str(ev.task)
    ET.SubElement(system, "Opcode").text = "0"
    ET.SubElement(system, "Keywords").text = _KEYWORDS.get(ev.channel, ev.keywords)

    time_created = ET.SubElement(system, "TimeCreated")
    time_created.set("SystemTime", format_system_time(ev.timestamp))

    ET.SubElement(system, "EventRecordID").text = str(ev.record_id)
    ET.SubElement(system, "Correlation")
    execution = ET.SubElement(system, "Execution")
    execution.set("ProcessID", "4")
    execution.set("ThreadID", "8")
    ET.SubElement(system, "Channel").text = _CHANNEL_PATH.get(ev.channel, ev.channel)
    ET.SubElement(system, "Computer").text = ev.computer
    ET.SubElement(system, "Security")

    # EventData
    event_data = ET.SubElement(event, "EventData")
    for key, value in ev.event_data.items():
        data_el = ET.SubElement(event_data, "Data")
        data_el.set("Name", key)
        data_el.text = str(value) if value is not None else ""

    return event


def _pretty_xml(root: ET.Element) -> str:
    raw = ET.tostring(root, encoding="unicode", xml_declaration=False)
    dom = xml.dom.minidom.parseString(raw)
    return dom.toprettyxml(indent="  ", encoding=None)


def export(bundle: ArtifactBundle, output_dir: Path) -> list[Path]:
    """Write one XML file per (host, channel). Return list of written paths."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Group events by (host, channel)
    groups: dict[tuple[str, str], list[GeneratedEvent]] = defaultdict(list)
    for ev in bundle.events:
        groups[(ev.host, ev.channel)].append(ev)

    written: list[Path] = []

    for (host, channel), events in sorted(groups.items()):
        root = ET.Element("Events")
        for ev in sorted(events, key=lambda e: e.timestamp):
            root.append(_build_event_element(ev))

        xml_str = _pretty_xml(root)
        filename = f"{host}_{channel}.xml"
        out_path = output_dir / filename
        out_path.write_text(xml_str, encoding="utf-8")
        written.append(out_path)

    return written
