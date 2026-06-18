"""Windows PowerShell channel event generators.

EID 4103 — Module Logging (pipeline execution details)
EID 4104 — Script Block Logging (script block text captured)

Channel: Microsoft-Windows-PowerShell/Operational
Provider: Microsoft-Windows-PowerShell
"""

from __future__ import annotations

import random
from typing import Any

from artiforge.core.models import Host, User
from artiforge.core.timeline import format_system_time


def _script_block_id() -> str:
    """Random GUID using the seeded random module so --seed produces deterministic output."""
    parts = [
        f"{random.getrandbits(32):08X}",
        f"{random.getrandbits(16):04X}",
        f"{(random.getrandbits(12) | 0x4000):04X}",
        f"{(random.getrandbits(14) | 0x8000):04X}",
        f"{random.getrandbits(48):012X}",
    ]
    return "-".join(parts)


# ── EID 4103 — Module Logging ─────────────────────────────────────────────────

def eid_4103(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    user_str = f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"
    return {
        "Payload": fields.get(
            "Payload",
            "CommandInvocation(Out-Default): \"Out-Default\"\n"
            "ParameterBinding(Out-Default): name=\"InputObject\"; "
            "value=\"CommandInvocation(Compress-Archive)\"",
        ),
        "ContextInfo": fields.get(
            "ContextInfo",
            f"        Severity = Informational\n"
            f"        Host Name = ConsoleHost\n"
            f"        Host Version = 5.1.19041.1\n"
            f"        Engine Version = 5.1.19041.1\n"
            f"        Runspace ID = {_script_block_id()}\n"
            f"        Pipeline ID = {random.randint(1, 20)}\n"
            f"        Command Name = {fields.get('CommandName', 'Compress-Archive')}\n"
            f"        Command Type = Cmdlet\n"
            f"        Script Name = {fields.get('ScriptName', '')}\n"
            f"        Command Path = \n"
            f"        Sequence Number = {random.randint(1, 50)}\n"
            f"        User = {user_str}\n"
            f"        Connected User = \n"
            f"        Shell ID = Microsoft.PowerShell",
        ),
    }


# ── EID 4104 — Script Block Logging ───────────────────────────────────────────

def eid_4104(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    script_text = fields.get(
        "ScriptBlockText",
        'Compress-Archive -Path "C:\\Users\\Public\\Documents\\*" '
        '-DestinationPath "C:\\Temp\\archive.zip"',
    )
    return {
        "MessageNumber": str(fields.get("MessageNumber", "1")),
        "MessageTotal": str(fields.get("MessageTotal", "1")),
        "ScriptBlockText": script_text,
        "ScriptBlockId": fields.get("ScriptBlockId", _script_block_id()),
        "Path": fields.get("Path", ""),
    }


# ── EID 4105 — Script Start ───────────────────────────────────────────────────

def eid_4105(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    return {
        "SequenceNumber": str(fields.get("SequenceNumber", "1")),
        "HostName": fields.get("HostName", "ConsoleHost"),
        "HostVersion": fields.get("HostVersion", "5.1.19041.1"),
        "HostId": fields.get("HostId", _script_block_id()),
        "HostApplication": fields.get("HostApplication", "powershell.exe"),
        "EngineVersion": fields.get("EngineVersion", "5.1.19041.1"),
        "RunspaceId": fields.get("RunspaceId", _script_block_id()),
        "ScriptName": fields.get("ScriptName", ""),
        "CommandLine": fields.get("CommandLine", ""),
    }


# ── EID 4106 — Script Stop ────────────────────────────────────────────────────

def eid_4106(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    return {
        "SequenceNumber": str(fields.get("SequenceNumber", "1")),
        "HostName": fields.get("HostName", "ConsoleHost"),
        "HostVersion": fields.get("HostVersion", "5.1.19041.1"),
        "HostId": fields.get("HostId", _script_block_id()),
        "HostApplication": fields.get("HostApplication", "powershell.exe"),
        "EngineVersion": fields.get("EngineVersion", "5.1.19041.1"),
        "RunspaceId": fields.get("RunspaceId", _script_block_id()),
        "ScriptName": fields.get("ScriptName", ""),
        "CommandLine": fields.get("CommandLine", ""),
    }


# ── EID 40961 — Engine Start ──────────────────────────────────────────────────

def eid_40961(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    return {
        "HostName": fields.get("HostName", "ConsoleHost"),
        "HostVersion": fields.get("HostVersion", "5.1.19041.1"),
        "HostId": fields.get("HostId", _script_block_id()),
        "HostApplication": fields.get("HostApplication", "powershell.exe"),
        "EngineVersion": fields.get("EngineVersion", "5.1.19041.1"),
        "RunspaceId": fields.get("RunspaceId", _script_block_id()),
    }


# ── EID 40962 — Engine Stop ───────────────────────────────────────────────────

def eid_40962(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    return {
        "HostName": fields.get("HostName", "ConsoleHost"),
        "HostVersion": fields.get("HostVersion", "5.1.19041.1"),
        "HostId": fields.get("HostId", _script_block_id()),
        "HostApplication": fields.get("HostApplication", "powershell.exe"),
        "EngineVersion": fields.get("EngineVersion", "5.1.19041.1"),
        "RunspaceId": fields.get("RunspaceId", _script_block_id()),
    }


# ── Dispatcher ────────────────────────────────────────────────────────────────

_GENERATORS = {
    4103: eid_4103,
    4104: eid_4104,
    4105: eid_4105,
    4106: eid_4106,
    40961: eid_40961,
    40962: eid_40962,
}


def generate(eid: int, fields: dict, host: Host, user: User | None,
             spec: Any, timestamp: Any, ctx: Any = None,
             session_label: str = "default",
             process_label: str = "default") -> dict:
    fn = _GENERATORS.get(eid)
    if fn is None:
        raise ValueError(f"PowerShell EID {eid} not implemented.")
    return fn(fields=fields, host=host, user=user, spec=spec, timestamp=timestamp,
              ctx=ctx, session_label=session_label, process_label=process_label)
