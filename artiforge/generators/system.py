"""Windows System channel event generators."""

from __future__ import annotations

from typing import Any

from artiforge.core.models import Host, User


# ── EID 7036 — Service State Changed ─────────────────────────────────────────

def eid_7036(fields: dict, **_) -> dict:
    return {
        "param1": fields.get("param1", "Wuauserv_Svc"),
        "param2": fields.get("param2", "running"),
    }


# ── EID 7031 — Service Crash ─────────────────────────────────────────────────

def eid_7031(fields: dict, **_) -> dict:
    return {
        "param1": fields.get("param1", "WindowsUpdateSvc"),
        "param2": fields.get("param2", "Restart the service"),
        "param3": fields.get("param3", "60000"),
        "param4": fields.get("param4", "1"),
    }


# ── EID 7034 — Service Terminated ─────────────────────────────────────────────

def eid_7034(fields: dict, **_) -> dict:
    return {
        "param1": fields.get("param1", "WindowsUpdateSvc"),
        "param2": fields.get("param2", "1"),
    }


# ── EID 7045 — New Service Installed ──────────────────────────────────────────

def eid_7045(fields: dict, **_) -> dict:
    return {
        "ServiceName": fields.get("ServiceName", "Wuauserv_Svc"),
        "ImagePath": fields.get(
            "ImagePath",
            r"C:\ProgramData\Microsoft\Windows\update.exe tunnel run --token FAKE_TOKEN",
        ),
        "ServiceType": fields.get("ServiceType", "user mode service"),
        "StartType": fields.get("StartType", "auto start"),
        "AccountName": fields.get("AccountName", "LocalSystem"),
    }


# ── Dispatcher ────────────────────────────────────────────────────────────────

_GENERATORS = {
    7031: eid_7031,
    7034: eid_7034,
    7036: eid_7036,
    7045: eid_7045,
}


def generate(eid: int, fields: dict, host: Host, user: User | None,
             spec: Any, timestamp: Any, ctx: Any = None,
             session_label: str = "default",
             process_label: str = "default") -> dict:
    fn = _GENERATORS.get(eid)
    if fn is None:
        raise ValueError(f"System EID {eid} not implemented.")
    return fn(fields=fields, host=host, user=user, spec=spec, timestamp=timestamp,
              ctx=ctx, session_label=session_label, process_label=process_label)
