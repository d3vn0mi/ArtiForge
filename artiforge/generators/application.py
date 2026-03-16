"""Windows Application channel event generators."""

from __future__ import annotations

from typing import Any

from artiforge.core.models import Host, User
from artiforge.core.timeline import format_system_time


# ── EID 1 — Application Error / Startup (used for Cloudflared log entries) ───

def eid_1(fields: dict, timestamp: Any, **_) -> dict:
    return {
        "Data": fields.get(
            "Data",
            "2026-02-19T09:42:01Z ERR Failed to create tunnel "
            "error=\"failed to connect to edge: dial tcp "
            "198.41.192.227:443: connect: connection timed out\"",
        ),
    }


# ── Dispatcher ────────────────────────────────────────────────────────────────

_GENERATORS = {
    1: eid_1,
}


def generate(eid: int, fields: dict, host: Host, user: User | None,
             spec: Any, timestamp: Any) -> dict:
    fn = _GENERATORS.get(eid)
    if fn is None:
        raise ValueError(f"Application EID {eid} not implemented.")
    return fn(fields=fields, host=host, user=user, spec=spec, timestamp=timestamp)
