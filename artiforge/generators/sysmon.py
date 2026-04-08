"""Sysmon event generators (Microsoft-Windows-Sysmon/Operational).

EID 1  — Process Create
EID 3  — Network Connection
EID 11 — File Created
EID 13 — Registry Value Set
"""

from __future__ import annotations

import random
import uuid
from typing import Any

from artiforge.core.models import Host, User
from artiforge.core.timeline import format_system_time


def _pid() -> str:
    return str(random.randint(1000, 15000))


def _guid() -> str:
    return f"{{{str(uuid.uuid4()).upper()}}}"


def _stable_guid(seed: str) -> str:
    """Deterministic GUID derived from a seed string (uuid5 / DNS namespace).

    Use this when multiple events must share the same ProcessGuid — e.g. a
    Sysmon 1 process-create and its subsequent Sysmon 3 network events.
    Pass the same seed string to all correlated events.
    """
    return "{" + str(uuid.uuid5(uuid.NAMESPACE_DNS, seed)).upper() + "}"


# ── EID 1 — Process Create ────────────────────────────────────────────────────

def eid_1(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    image = fields.get("Image", r"C:\Windows\System32\cmd.exe")
    proc_name = image.split("\\")[-1] if "\\" in image else image
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": _guid(),
        "ProcessId": _pid(),
        "Image": image,
        "FileVersion": fields.get("FileVersion", "10.0.19041.1 (WinBuild.160101.0800)"),
        "Description": fields.get("Description", proc_name),
        "Product": fields.get("Product", "Microsoft Windows Operating System"),
        "Company": fields.get("Company", "Microsoft Corporation"),
        "OriginalFileName": fields.get("OriginalFileName", proc_name),
        "CommandLine": fields.get("CommandLine", image),
        "CurrentDirectory": fields.get("CurrentDirectory", r"C:\Windows\system32\\"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
        "LogonGuid": _guid(),
        "LogonId": hex(random.randint(0x10000, 0x9FFFF)),
        "TerminalSessionId": fields.get("TerminalSessionId", "1"),
        "IntegrityLevel": fields.get("IntegrityLevel", "High"),
        "Hashes": fields.get("Hashes", f"MD5={_fake_md5()},SHA256={_fake_sha256()}"),
        "ParentProcessGuid": _guid(),
        "ParentProcessId": _pid(),
        "ParentImage": fields.get("ParentImage", r"C:\Windows\System32\cmd.exe"),
        "ParentCommandLine": fields.get("ParentCommandLine", ""),
        "ParentUser": fields.get("ParentUser", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 3 — Network Connection ────────────────────────────────────────────────

def eid_3(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": _guid(),
        "ProcessId": _pid(),
        "Image": fields.get("Image", r"C:\Windows\System32\cmd.exe"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
        "Protocol": fields.get("Protocol", "tcp"),
        "Initiated": fields.get("Initiated", "true"),
        "SourceIsIpv6": "false",
        "SourceIp": fields.get("SourceIp", host.ip),
        "SourceHostname": fields.get("SourceHostname", host.fqdn),
        "SourcePort": str(fields.get("SourcePort", random.randint(49152, 65535))),
        "SourcePortName": "-",
        "DestinationIsIpv6": "false",
        "DestinationIp": fields.get("DestinationIp", "198.41.192.227"),
        "DestinationHostname": fields.get("DestinationHostname", "region2.v2.argotunnel.com"),
        "DestinationPort": str(fields.get("DestinationPort", 443)),
        "DestinationPortName": fields.get("DestinationPortName", "https"),
    }


# ── EID 11 — File Created ─────────────────────────────────────────────────────

def eid_11(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": _guid(),
        "ProcessId": _pid(),
        "Image": fields.get("Image", r"C:\Windows\System32\cmd.exe"),
        "TargetFilename": fields.get("TargetFilename", r"C:\Temp\file.dat"),
        "CreationUtcTime": format_system_time(timestamp),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 13 — Registry Value Set ───────────────────────────────────────────────

def eid_13(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    return {
        "RuleName": fields.get("RuleName", "-"),
        "EventType": "SetValue",
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": _guid(),
        "ProcessId": _pid(),
        "Image": fields.get("Image", r"C:\Windows\System32\schtasks.exe"),
        "TargetObject": fields.get(
            "TargetObject",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
            r"\Tasks\{00000000-0000-0000-0000-000000000000}\Actions",
        ),
        "Details": fields.get("Details", "Binary Data"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fake_md5() -> str:
    import secrets
    return secrets.token_hex(16).upper()


def _fake_sha256() -> str:
    import secrets
    return secrets.token_hex(32).upper()


# ── Dispatcher ────────────────────────────────────────────────────────────────

_GENERATORS = {
    1:  eid_1,
    3:  eid_3,
    11: eid_11,
    13: eid_13,
}


def generate(eid: int, fields: dict, host: Host, user: User | None,
             spec: Any, timestamp: Any) -> dict:
    fn = _GENERATORS.get(eid)
    if fn is None:
        raise ValueError(f"Sysmon EID {eid} not implemented.")
    return fn(fields=fields, host=host, user=user, spec=spec, timestamp=timestamp)
