"""Generator registry — dispatches events and file artifacts to the right generator."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from artiforge.core.correlation import CorrelationContext
from artiforge.core.models import FileArtifactSpec, GeneratedFile, Host, LabSpec, Phase, User
from artiforge.generators import application, files, linux_auditd, powershell, security, sysmon, system, wmi

_CHANNEL_MAP = {
    "Security":    security,
    "System":      system,
    "Sysmon":      sysmon,
    "Application": application,
    "PowerShell":  powershell,
    "WMI":         wmi,
    "Auditd":      linux_auditd,
}


def dispatch_event(
    channel: str,
    eid: int,
    fields: dict,
    host: Host,
    user: User | None,
    spec: LabSpec,
    timestamp: datetime,
    ctx: CorrelationContext | None = None,
    session_label: str = "default",
    process_label: str = "default",
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
        ctx=ctx,
        session_label=session_label,
        process_label=process_label,
    )


def dispatch_file(fa_spec: FileArtifactSpec, phase: Phase) -> GeneratedFile | None:
    return files.generate(fa_spec, phase)
