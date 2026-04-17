"""Raw audit.log exporter for Linux auditd events.

Produces one audit.log file per Linux host in the native key=value format.
Windows events are silently skipped.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from artiforge.core.models import ArtifactBundle, GeneratedEvent

_RECORD_TYPES = {
    1300: "SYSCALL", 1309: "EXECVE", 1302: "PATH", 1306: "SOCKADDR",
    1100: "USER_AUTH", 1101: "USER_LOGIN", 1103: "CRED_ACQ",
}


def _format_record(ev):
    record_type = _RECORD_TYPES.get(ev.eid, f"UNKNOWN[{ev.eid}]")
    unix_ts = ev.timestamp.timestamp()
    serial = ev.record_id
    kv_pairs = " ".join(f"{k}={v}" for k, v in ev.event_data.items())
    return f"type={record_type} msg=audit({unix_ts:.3f}:{serial}): {kv_pairs}"


def export(bundle, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    groups = defaultdict(list)
    for ev in bundle.events:
        if ev.channel == "Auditd":
            groups[ev.host].append(ev)

    written = []
    for host, events in sorted(groups.items()):
        lines = [_format_record(ev) for ev in sorted(events, key=lambda e: e.timestamp)]
        out_path = output_dir / f"{host}_audit.log"
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(out_path)
    return written
