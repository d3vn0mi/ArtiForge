"""Sysmon event generators (Microsoft-Windows-Sysmon/Operational).

EID 1  — Process Create
EID 3  — Network Connection
EID 5  — Process Terminated
EID 7  — Image Loaded
EID 8  — CreateRemoteThread
EID 10 — ProcessAccess
EID 11 — File Created
EID 12 — RegistryEvent (ObjectCreate/Delete)
EID 13 — Registry Value Set
EID 14 — RegistryEvent (Key/Value Renamed)
EID 17 — Pipe Created
EID 18 — Pipe Connected
EID 22 — DNS Query
EID 15 — FileCreateStreamHash (ADS)
EID 16 — ServiceConfigurationChange
EID 22 — DNS Query
EID 23 — FileDelete
EID 24 — ClipboardChange
EID 25 — ProcessTampering
EID 26 — FileDeleteDetected
"""

from __future__ import annotations

import random
from typing import Any

from artiforge.core.correlation import CorrelationContext
from artiforge.core.models import Host, User
from artiforge.core.timeline import format_system_time


def _pid(category: str = "user") -> str:
    ranges = {
        "system":  (4, 800),
        "service": (800, 5000),
        "user":    (5000, 65535),
    }
    lo, hi = ranges.get(category, ranges["user"])
    return str(random.randint(lo // 4, hi // 4) * 4)


_PID_CATEGORIES = {
    "svchost.exe": "service", "lsass.exe": "service",
    "services.exe": "service", "System": "system",
    "smss.exe": "system", "csrss.exe": "system",
}


def _pid_for_image(image: str) -> str:
    name = image.rsplit("\\", 1)[-1] if "\\" in image else image
    return _pid(_PID_CATEGORIES.get(name, "user"))


def _resolve_process(fields: dict, ctx, process_label: str) -> tuple[str, str]:
    """Resolve ProcessGuid/ProcessId from fields, context, or random."""
    process_guid = fields.get("ProcessGuid")
    process_id = fields.get("ProcessId")
    if ctx is not None and process_guid is None:
        proc = ctx.get_process(process_label)
        if proc is not None:
            process_guid = proc.process_guid
            process_id = proc.process_id
    return process_guid or _guid(), process_id or _pid()


def _guid() -> str:
    """Random GUID using the seeded random module so --seed produces deterministic output."""
    parts = [
        f"{random.getrandbits(32):08X}",
        f"{random.getrandbits(16):04X}",
        f"{(random.getrandbits(12) | 0x4000):04X}",
        f"{(random.getrandbits(14) | 0x8000):04X}",
        f"{random.getrandbits(48):012X}",
    ]
    return "{" + "-".join(parts) + "}"



# ── EID 1 — Process Create ────────────────────────────────────────────────────

def eid_1(fields: dict, host: Host, user: User | None, timestamp: Any,
          ctx=None, session_label: str = "default",
          process_label: str = "default", **_) -> dict:
    image = fields.get("Image", r"C:\Windows\System32\cmd.exe")
    proc_name = image.split("\\")[-1] if "\\" in image else image

    process_guid = fields.get("ProcessGuid", _guid())
    process_id = fields.get("ProcessId", _pid_for_image(image))

    # Parent from context (current process becomes parent)
    parent_guid = fields.get("ParentProcessGuid")
    parent_id = fields.get("ParentProcessId")
    parent_image = fields.get("ParentImage")
    if ctx is not None and parent_guid is None:
        current = ctx.get_process(process_label)
        if current is not None:
            parent_guid = current.process_guid
            parent_id = current.process_id
            parent_image = parent_image or current.image
    parent_guid = parent_guid or _guid()
    parent_id = parent_id or _pid()
    parent_image = parent_image or r"C:\Windows\System32\cmd.exe"

    # Logon from session context
    logon_guid = fields.get("LogonGuid")
    logon_id = fields.get("LogonId")
    if ctx is not None and logon_guid is None:
        session = ctx.get_session(session_label)
        if session is not None:
            logon_guid = session.logon_guid
            logon_id = session.logon_id
    logon_guid = logon_guid or _guid()
    logon_id = logon_id or hex(random.randint(0x10000, 0x9FFFF))

    # Producer: register process
    if ctx is not None:
        ctx.register_process(process_guid, process_id, image, label=process_label)

    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "Image": image,
        "FileVersion": fields.get("FileVersion", "10.0.19041.1 (WinBuild.160101.0800)"),
        "Description": fields.get("Description", proc_name),
        "Product": fields.get("Product", "Microsoft Windows Operating System"),
        "Company": fields.get("Company", "Microsoft Corporation"),
        "OriginalFileName": fields.get("OriginalFileName", proc_name),
        "CommandLine": fields.get("CommandLine", image),
        "CurrentDirectory": fields.get("CurrentDirectory", r"C:\Windows\system32\\"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
        "LogonGuid": logon_guid,
        "LogonId": logon_id,
        "TerminalSessionId": fields.get("TerminalSessionId", "1"),
        "IntegrityLevel": fields.get("IntegrityLevel", "High"),
        "Hashes": fields.get("Hashes", f"MD5={_fake_md5()},SHA256={_fake_sha256()}"),
        "ParentProcessGuid": parent_guid,
        "ParentProcessId": parent_id,
        "ParentImage": parent_image,
        "ParentCommandLine": fields.get("ParentCommandLine", ""),
        "ParentUser": fields.get("ParentUser", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 3 — Network Connection ────────────────────────────────────────────────

def eid_3(fields: dict, host: Host, user: User | None, timestamp: Any,
          ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
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

def eid_11(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "Image": fields.get("Image", r"C:\Windows\System32\cmd.exe"),
        "TargetFilename": fields.get("TargetFilename", r"C:\Temp\file.dat"),
        "CreationUtcTime": format_system_time(timestamp),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 13 — Registry Value Set ───────────────────────────────────────────────

def eid_13(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "EventType": "SetValue",
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "Image": fields.get("Image", r"C:\Windows\System32\schtasks.exe"),
        "TargetObject": fields.get(
            "TargetObject",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
            r"\Tasks\{00000000-0000-0000-0000-000000000000}\Actions",
        ),
        "Details": fields.get("Details", "Binary Data"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 5 — Process Terminated ────────────────────────────────────────────────

def eid_5(fields: dict, host: Host, user: User | None, timestamp: Any,
          ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "Image": fields.get("Image", r"C:\Windows\System32\cmd.exe"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 7 — Image Loaded ──────────────────────────────────────────────────────

def eid_7(fields: dict, host: Host, user: User | None, timestamp: Any,
          ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    image_loaded = fields.get("ImageLoaded", r"C:\Windows\System32\ntdll.dll")
    dll_name = image_loaded.split("\\")[-1] if "\\" in image_loaded else image_loaded
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "Image": fields.get("Image", r"C:\Windows\System32\rundll32.exe"),
        "ImageLoaded": image_loaded,
        "FileVersion": fields.get("FileVersion", "10.0.19041.1 (WinBuild.160101.0800)"),
        "Description": fields.get("Description", dll_name),
        "Product": fields.get("Product", "Microsoft Windows Operating System"),
        "Company": fields.get("Company", "Microsoft Corporation"),
        "OriginalFileName": fields.get("OriginalFileName", dll_name),
        "Hashes": fields.get("Hashes", f"MD5={_fake_md5()},SHA256={_fake_sha256()}"),
        "Signed": fields.get("Signed", "true"),
        "Signature": fields.get("Signature", "Microsoft Windows"),
        "SignatureStatus": fields.get("SignatureStatus", "Valid"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 8 — CreateRemoteThread ────────────────────────────────────────────────

def eid_8(fields: dict, host: Host, user: User | None, timestamp: Any,
          ctx=None, process_label: str = "default", **_) -> dict:
    # Source from context
    src_guid = fields.get("SourceProcessGuid")
    src_id = fields.get("SourceProcessId")
    if ctx is not None and src_guid is None:
        proc = ctx.get_process(process_label)
        if proc is not None:
            src_guid = proc.process_guid
            src_id = proc.process_id
    src_guid = src_guid or _guid()
    src_id = src_id or _pid()
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "SourceProcessGuid": src_guid,
        "SourceProcessId": src_id,
        "SourceImage": fields.get("SourceImage", r"C:\Windows\System32\cmd.exe"),
        "TargetProcessGuid": fields.get("TargetProcessGuid", _guid()),
        "TargetProcessId": _pid(),
        "TargetImage": fields.get("TargetImage", r"C:\Windows\System32\lsass.exe"),
        "NewThreadId": str(random.randint(1000, 9999)),
        "StartAddress": fields.get("StartAddress",
            f"0x{random.randint(0x7FF000000000, 0x7FFFFFFFFFFF):016X}"),
        "StartModule": fields.get("StartModule", r"C:\Windows\System32\ntdll.dll"),
        "StartFunction": fields.get("StartFunction", "-"),
        "SourceUser": fields.get("SourceUser",
            f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
        "TargetUser": fields.get("TargetUser", "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 10 — ProcessAccess ────────────────────────────────────────────────────

def eid_10(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    # Source from context
    src_guid = fields.get("SourceProcessGuid")
    src_id = fields.get("SourceProcessId")
    if ctx is not None and src_guid is None:
        proc = ctx.get_process(process_label)
        if proc is not None:
            src_guid = proc.process_guid
            src_id = proc.process_id
    src_guid = src_guid or _guid()
    src_id = src_id or _pid()
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "SourceProcessGuid": src_guid,
        "SourceProcessId": src_id,
        "SourceThreadId": str(random.randint(1000, 9999)),
        "SourceImage": fields.get("SourceImage", r"C:\Windows\System32\cmd.exe"),
        "TargetProcessGuid": fields.get("TargetProcessGuid", _guid()),
        "TargetProcessId": _pid(),
        "TargetImage": fields.get("TargetImage", r"C:\Windows\System32\lsass.exe"),
        "GrantedAccess": fields.get("GrantedAccess", "0x1010"),
        "CallTrace": fields.get("CallTrace",
            r"C:\Windows\System32\ntdll.dll+0x9d014|UNKNOWN"),
        "SourceUser": fields.get("SourceUser",
            f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
        "TargetUser": fields.get("TargetUser", "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 12 — RegistryEvent (Object Create/Delete) ─────────────────────────────

def eid_12(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "EventType": fields.get("EventType", "CreateKey"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "Image": fields.get("Image", r"C:\Windows\System32\reg.exe"),
        "TargetObject": fields.get("TargetObject",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 14 — RegistryEvent (Key/Value Renamed) ────────────────────────────────

def eid_14(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "EventType": fields.get("EventType", "RenameKey"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "Image": fields.get("Image", r"C:\Windows\System32\reg.exe"),
        "TargetObject": fields.get("TargetObject",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater"),
        "NewName": fields.get("NewName",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 17 — Pipe Created ─────────────────────────────────────────────────────

def eid_17(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "EventType": "CreatePipe",
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "PipeName": fields.get("PipeName", r"\\.\pipe\MSSE-1234-server"),
        "Image": fields.get("Image", r"C:\Windows\System32\cmd.exe"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 18 — Pipe Connected ───────────────────────────────────────────────────

def eid_18(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "EventType": "ConnectPipe",
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "PipeName": fields.get("PipeName", r"\\.\pipe\MSSE-1234-server"),
        "Image": fields.get("Image", r"C:\Windows\System32\svchost.exe"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 22 — DNS Query ───────────────────────────────────────────────────────

def eid_22(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "QueryName": fields.get("QueryName", "region2.v2.argotunnel.com"),
        "QueryStatus": fields.get("QueryStatus", "0"),
        "QueryResults": fields.get("QueryResults", "type:  5 region2.v2.argotunnel.com;198.41.192.227;"),
        "Image": fields.get("Image", r"C:\Windows\System32\cmd.exe"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 23 — FileDelete ───────────────────────────────────────────────────────

def eid_23(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
        "Image": fields.get("Image", r"C:\Windows\System32\cmd.exe"),
        "TargetFilename": fields.get("TargetFilename", r"C:\Temp\payload.exe"),
        "Hashes": fields.get("Hashes", f"MD5={_fake_md5()},SHA256={_fake_sha256()}"),
        "IsExecutable": fields.get("IsExecutable", "true"),
        "Archived": fields.get("Archived", "false"),
    }


# ── EID 25 — ProcessTampering ─────────────────────────────────────────────────

def eid_25(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "Image": fields.get("Image", r"C:\Windows\System32\svchost.exe"),
        "Type": fields.get("Type", "Image is locked for reading"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 6 — Driver Loaded ─────────────────────────────────────────────────────

def eid_6(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ImageLoaded": fields.get("ImageLoaded", r"C:\Windows\System32\drivers\svchost.sys"),
        "Hashes": fields.get("Hashes", f"MD5={_fake_md5()},SHA256={_fake_sha256()}"),
        "Signed": fields.get("Signed", "false"),
        "Signature": fields.get("Signature", "-"),
        "SignatureStatus": fields.get("SignatureStatus", "Unavailable"),
    }


# ── EID 15 — FileCreateStreamHash (ADS) ──────────────────────────────────────

def eid_15(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "Image": fields.get("Image", r"C:\Windows\System32\cmd.exe"),
        "TargetFilename": fields.get("TargetFilename", r"C:\Temp\file.txt:hidden"),
        "CreationUtcTime": format_system_time(timestamp),
        "Hash": fields.get("Hash", f"MD5={_fake_md5()},SHA256={_fake_sha256()}"),
        "Contents": fields.get("Contents", "Binary Data"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 16 — ServiceConfigurationChange ──────────────────────────────────────

def eid_16(fields: dict, host: Host, user: User | None, timestamp: Any, **_) -> dict:
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "Configuration": fields.get("Configuration", r"C:\Windows\SysmonDrv.sys"),
        "ConfigurationFileHash": fields.get("ConfigurationFileHash", f"SHA256={_fake_sha256()}"),
    }


# ── EID 24 — ClipboardChange ─────────────────────────────────────────────────

def eid_24(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "Image": fields.get("Image", r"C:\Windows\System32\cmd.exe"),
        "Session": fields.get("Session", "1"),
        "ClientInfo": fields.get("ClientInfo", "user session"),
        "Hashes": fields.get("Hashes", f"MD5={_fake_md5()},SHA256={_fake_sha256()}"),
        "Archived": fields.get("Archived", "true"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
    }


# ── EID 26 — FileDeleteDetected ───────────────────────────────────────────────

def eid_26(fields: dict, host: Host, user: User | None, timestamp: Any,
           ctx=None, process_label: str = "default", **_) -> dict:
    process_guid, process_id = _resolve_process(fields, ctx, process_label)
    return {
        "RuleName": fields.get("RuleName", "-"),
        "UtcTime": format_system_time(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
        "Image": fields.get("Image", r"C:\Windows\System32\cmd.exe"),
        "TargetFilename": fields.get("TargetFilename", r"C:\Temp\payload.exe"),
        "Hashes": fields.get("Hashes", f"MD5={_fake_md5()},SHA256={_fake_sha256()}"),
        "IsExecutable": fields.get("IsExecutable", "true"),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fake_md5() -> str:
    return ''.join(f'{random.getrandbits(8):02X}' for _ in range(16))


def _fake_sha256() -> str:
    return ''.join(f'{random.getrandbits(8):02X}' for _ in range(32))


# ── Dispatcher ────────────────────────────────────────────────────────────────

_GENERATORS = {
    1:  eid_1,
    3:  eid_3,
    5:  eid_5,
    6:  eid_6,
    7:  eid_7,
    8:  eid_8,
    10: eid_10,
    11: eid_11,
    12: eid_12,
    13: eid_13,
    14: eid_14,
    15: eid_15,
    16: eid_16,
    17: eid_17,
    18: eid_18,
    22: eid_22,
    23: eid_23,
    24: eid_24,
    25: eid_25,
    26: eid_26,
}


def generate(eid: int, fields: dict, host: Host, user: User | None,
             spec: Any, timestamp: Any, ctx: Any = None,
             session_label: str = "default",
             process_label: str = "default") -> dict:
    fn = _GENERATORS.get(eid)
    if fn is None:
        raise ValueError(f"Sysmon EID {eid} not implemented.")
    return fn(fields=fields, host=host, user=user, spec=spec, timestamp=timestamp,
              ctx=ctx, session_label=session_label, process_label=process_label)
