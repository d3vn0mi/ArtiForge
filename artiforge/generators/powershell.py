"""Windows PowerShell channel event generators.

EID 4103 — Module Logging (pipeline execution details)
EID 4104 — Script Block Logging (script block text captured)

Channel: Microsoft-Windows-PowerShell/Operational
Provider: Microsoft-Windows-PowerShell
"""

from __future__ import annotations

import random
import uuid
from typing import Any

from artiforge.core.models import Host, User
from artiforge.core.timeline import format_system_time


def _script_block_id() -> str:
    return str(uuid.uuid4()).upper()


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


# ── Dispatcher ────────────────────────────────────────────────────────────────

_GENERATORS = {
    4103: eid_4103,
    4104: eid_4104,
}


def generate(eid: int, fields: dict, host: Host, user: User | None,
             spec: Any, timestamp: Any) -> dict:
    fn = _GENERATORS.get(eid)
    if fn is None:
        raise ValueError(f"PowerShell EID {eid} not implemented.")
    return fn(fields=fields, host=host, user=user, spec=spec, timestamp=timestamp)
