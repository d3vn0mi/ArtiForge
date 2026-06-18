"""EVTX binary exporter — produces .evtx files via evtxforge.

One file per (host, channel) pair, matching the XML exporter convention.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from artiforge.core.models import ArtifactBundle, GeneratedEvent
from evtxforge import EvtxWriter

_CHANNEL_PATH = {
    "Security":    "Security",
    "System":      "System",
    "Sysmon":      "Microsoft-Windows-Sysmon/Operational",
    "Application": "Application",
    "PowerShell":  "Microsoft-Windows-PowerShell/Operational",
    "WMI":         "Microsoft-Windows-WMI-Activity/Operational",
}


def export(bundle: ArtifactBundle, output_dir: Path) -> list[Path]:
    """Write one .evtx file per (host, channel) pair. Return written paths."""
    output_dir.mkdir(parents=True, exist_ok=True)

    groups: dict[tuple[str, str], list[GeneratedEvent]] = defaultdict(list)
    for ev in bundle.events:
        groups[(ev.host, ev.channel)].append(ev)

    written: list[Path] = []

    for (host, channel), events in sorted(groups.items()):
        filename = f"{host}_{channel}.evtx"
        out_path = output_dir / filename

        with EvtxWriter(out_path) as writer:
            for ev in sorted(events, key=lambda e: e.timestamp):
                writer.write_event(
                    channel=_CHANNEL_PATH.get(ev.channel, ev.channel),
                    event_id=ev.eid,
                    provider_name=ev.provider_name,
                    provider_guid=ev.provider_guid,
                    computer=ev.computer,
                    timestamp=ev.timestamp,
                    event_data=ev.event_data,
                    record_id=ev.record_id,
                    level=ev.level,
                    task=ev.task,
                )

        written.append(out_path)

    return written
