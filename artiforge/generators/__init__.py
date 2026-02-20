"""Generator registry — dispatches events and file artifacts to the right generator."""

from __future__ import annotations

from typing import Any

from artiforge.core.models import FileArtifactSpec, GeneratedFile, Host, Phase, User
from artiforge.generators import application, files, security, sysmon, system

_CHANNEL_MAP = {
    "Security":    security,
    "System":      system,
    "Sysmon":      sysmon,
    "Application": application,
}


def dispatch_event(
    channel: str,
    eid: int,
    fields: dict,
    host: Host,
    user: User | None,
    spec: Any,
    timestamp: Any,
) -> dict:
    mod = _CHANNEL_MAP.get(channel)
    if mod is None:
        raise ValueError(
            f"Unknown channel '{channel}'. Available: {list(_CHANNEL_MAP)}"
        )
    return mod.generate(
        eid=eid,
        fields=fields,
        host=host,
        user=user,
        spec=spec,
        timestamp=timestamp,
    )


def dispatch_file(fa_spec: FileArtifactSpec, phase: Phase) -> GeneratedFile | None:
    return files.generate(fa_spec, phase)
