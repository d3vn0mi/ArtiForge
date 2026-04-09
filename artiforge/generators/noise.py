"""Background noise event generators.

Produces benign-looking Windows events that are injected into the lab timeline
to make it more realistic. Trainees must filter these out while hunting.

All noise events are tagged phase_id=0 / phase_name="noise" so they can be
excluded from scoring but appear in Kibana alongside attack events.
"""

from __future__ import annotations

import random
import secrets
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from artiforge.core.models import GeneratedEvent, Host, NoiseSpec, User
from artiforge.core.timeline import format_system_time

if TYPE_CHECKING:
    from artiforge.core.models import LabSpec


# ── Common process allowlist ──────────────────────────────────────────────────
# Tuples of (image, parent_image, description)

_COMMON_PROCESSES = [
    (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Windows\explorer.exe",
        "Google Chrome",
    ),
    (
        r"C:\Windows\System32\svchost.exe",
        r"C:\Windows\System32\services.exe",
        "Host Process for Windows Services",
    ),
    (
        r"C:\Windows\System32\taskhostw.exe",
        r"C:\Windows\System32\svchost.exe",
        "Host Process for Windows Tasks",
    ),
    (
        r"C:\Windows\System32\RuntimeBroker.exe",
        r"C:\Windows\System32\svchost.exe",
        "Runtime Broker",
    ),
    (
        r"C:\Windows\System32\SearchIndexer.exe",
        r"C:\Windows\System32\services.exe",
        "Microsoft Windows Search Indexer",
    ),
    (
        r"C:\Windows\System32\dllhost.exe",
        r"C:\Windows\System32\svchost.exe",
        "COM Surrogate",
    ),
    (
        r"C:\Windows\System32\conhost.exe",
        r"C:\Windows\System32\svchost.exe",
        "Console Window Host",
    ),
    (
        r"C:\Windows\System32\WmiPrvSE.exe",
        r"C:\Windows\System32\svchost.exe",
        "WMI Provider Host",
    ),
    (
        r"C:\Windows\System32\MsMpEng.exe",
        r"C:\Windows\System32\services.exe",
        "Antimalware Service Executable",
    ),
    (
        r"C:\Windows\System32\backgroundTaskHost.exe",
        r"C:\Windows\System32\svchost.exe",
        "Background Task Host",
    ),
    (
        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        r"C:\Windows\explorer.exe",
        "Microsoft Word",
    ),
    (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Windows\explorer.exe",
        "Microsoft Edge",
    ),
    (
        r"C:\Windows\System32\msiexec.exe",
        r"C:\Windows\System32\svchost.exe",
        "Windows Installer",
    ),
]

# ── Common DNS queries ────────────────────────────────────────────────────────

_COMMON_DOMAINS = [
    ("www.google.com", "142.250.80.100"),
    ("www.microsoft.com", "23.203.6.136"),
    ("update.microsoft.com", "23.203.6.140"),
    ("ctldl.windowsupdate.com", "13.107.4.52"),
    ("wustat.windows.com", "40.76.4.15"),
    ("www.bing.com", "204.79.197.200"),
    ("clients2.google.com", "142.250.80.110"),
    ("dl.google.com", "142.250.80.120"),
    ("ocsp.digicert.com", "93.184.220.29"),
    ("watson.microsoft.com", "13.107.246.40"),
    ("settings-win.data.microsoft.com", "40.83.189.116"),
    ("config.teams.microsoft.com", "52.114.128.0"),
    ("login.microsoftonline.com", "20.190.128.0"),
    ("graph.microsoft.com", "20.231.239.246"),
]

# ── Helpers ───────────────────────────────────────────────────────────────────

_SECURITY_PROVIDER = ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}")
_SYSMON_PROVIDER   = ("Microsoft-Windows-Sysmon",            "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}")


def _pid() -> str:
    return str(random.randint(1000, 15000))


def _guid() -> str:
    parts = [
        f"{random.getrandbits(32):08X}",
        f"{random.getrandbits(16):04X}",
        f"{(random.getrandbits(12) | 0x4000):04X}",
        f"{(random.getrandbits(14) | 0x8000):04X}",
        f"{random.getrandbits(48):012X}",
    ]
    return "{" + "-".join(parts) + "}"


def _fake_md5() -> str:
    return secrets.token_hex(16).upper()


def _fake_sha256() -> str:
    return secrets.token_hex(32).upper()


def _logon_id() -> str:
    n = random.randint(0x100000, 0xFFFFFF)
    return f"0x{n:x}"


def _make_event(
    record_id: int,
    timestamp: datetime,
    channel: str,
    eid: int,
    host: Host,
    provider: tuple[str, str],
    event_data: dict,
) -> GeneratedEvent:
    prov_name, prov_guid = provider
    return GeneratedEvent(
        record_id=record_id,
        timestamp=timestamp,
        channel=channel,
        eid=eid,
        host=host.name,
        computer=host.fqdn,
        provider_name=prov_name,
        provider_guid=prov_guid,
        event_data={k: str(v) for k, v in event_data.items()},
        phase_id=0,
        phase_name="noise",
    )


# ── Noise generators ──────────────────────────────────────────────────────────

def logon_pair(
    host: Host,
    user: User,
    ts: datetime,
    record_id_start: int,
) -> list[GeneratedEvent]:
    """Security 4624 (logon) + 4634 (logoff) separated by a short session."""
    logon_id = _logon_id()
    logon_type = random.choice(["2", "2", "3", "10"])  # interactive, network, RDP
    session_minutes = random.randint(5, 45)

    logon_data = {
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": "-",
        "SubjectDomainName": "-",
        "SubjectLogonId": "0x3e7",
        "TargetUserSid": host.user_sid(user.rid),
        "TargetUserName": user.username,
        "TargetDomainName": user.domain,
        "TargetLogonId": logon_id,
        "LogonType": logon_type,
        "LogonProcessName": "User32" if logon_type in ("2", "10") else "NtLmSsp",
        "AuthenticationPackageName": "Negotiate",
        "WorkstationName": host.name,
        "LogonGuid": _guid(),
        "TransmittedServices": "-",
        "LmPackageName": "-",
        "KeyLength": "0",
        "ProcessId": _pid(),
        "ProcessName": r"C:\Windows\System32\winlogon.exe",
        "IpAddress": "-",
        "IpPort": "-",
        "ImpersonationLevel": "%%1833",
        "RestrictedAdminMode": "-",
        "RemoteCredentialGuard": "-",
        "TargetOutboundUserName": "-",
        "TargetOutboundDomainName": "-",
        "VirtualAccount": "%%1843",
        "TargetLinkedLogonId": "0x0",
        "ElevatedToken": "%%1842",
    }

    logoff_data = {
        "TargetUserSid": host.user_sid(user.rid),
        "TargetUserName": user.username,
        "TargetDomainName": user.domain,
        "TargetLogonId": logon_id,
        "LogonType": logon_type,
    }

    logoff_ts = ts + timedelta(minutes=session_minutes)

    return [
        _make_event(record_id_start, ts, "Security", 4624, host, _SECURITY_PROVIDER, logon_data),
        _make_event(record_id_start + 1, logoff_ts, "Security", 4634, host, _SECURITY_PROVIDER, logoff_data),
    ]


def process_spawn(
    host: Host,
    user: User,
    ts: datetime,
    record_id: int,
) -> GeneratedEvent:
    """Sysmon EID 1 — a benign process from the common allowlist."""
    image, parent, description = random.choice(_COMMON_PROCESSES)
    proc_name = image.split("\\")[-1]
    parent_name = parent.split("\\")[-1]

    event_data = {
        "RuleName": "-",
        "UtcTime": format_system_time(ts),
        "ProcessGuid": _guid(),
        "ProcessId": _pid(),
        "Image": image,
        "FileVersion": "10.0.19041.1",
        "Description": description,
        "Product": "Microsoft Windows Operating System",
        "Company": "Microsoft Corporation",
        "OriginalFileName": proc_name,
        "CommandLine": image,
        "CurrentDirectory": r"C:\Windows\system32\\",
        "User": user.full,
        "LogonGuid": _guid(),
        "LogonId": hex(random.randint(0x10000, 0x9FFFF)),
        "TerminalSessionId": "1",
        "IntegrityLevel": "Medium",
        "Hashes": f"MD5={_fake_md5()},SHA256={_fake_sha256()}",
        "ParentProcessGuid": _guid(),
        "ParentProcessId": _pid(),
        "ParentImage": parent,
        "ParentCommandLine": parent_name,
        "ParentUser": user.full,
    }

    return _make_event(record_id, ts, "Sysmon", 1, host, _SYSMON_PROVIDER, event_data)


def dns_query(
    host: Host,
    user: User,
    ts: datetime,
    record_id: int,
) -> GeneratedEvent:
    """Sysmon EID 22 — a benign DNS lookup from the common domain list."""
    image, parent, description = random.choice(_COMMON_PROCESSES)
    domain, ip = random.choice(_COMMON_DOMAINS)

    event_data = {
        "RuleName": "-",
        "UtcTime": format_system_time(ts),
        "ProcessGuid": _guid(),
        "ProcessId": _pid(),
        "QueryName": domain,
        "QueryStatus": "0",
        "QueryResults": f"type:  1 {ip};",
        "Image": image,
        "User": user.full,
    }

    return _make_event(record_id, ts, "Sysmon", 22, host, _SYSMON_PROVIDER, event_data)


# ── Noise injection orchestrator ──────────────────────────────────────────────

def generate(
    noise_spec: NoiseSpec,
    host: Host,
    base_time: datetime,
    record_id_start: int,
) -> list[GeneratedEvent]:
    """Generate all noise events for a single NoiseSpec entry.

    Events are scattered randomly within [base_time, base_time + spread_minutes].
    Returns them sorted by timestamp. The caller assigns final record IDs.
    """
    events: list[GeneratedEvent] = []
    spread_seconds = noise_spec.spread_minutes * 60

    # Choose a realistic user for noise (first user on host, or SYSTEM)
    if host.users:
        noise_user = host.users[0]
    else:
        noise_user = User(username="SYSTEM", domain="NT AUTHORITY", rid=18)

    rid = record_id_start

    # Logon/logoff pairs
    for _ in range(noise_spec.logon_pairs):
        ts = base_time + timedelta(seconds=random.randint(0, spread_seconds))
        pair = logon_pair(host, noise_user, ts, rid)
        events.extend(pair)
        rid += len(pair)

    # Process spawns
    for _ in range(noise_spec.process_spawns):
        ts = base_time + timedelta(seconds=random.randint(0, spread_seconds))
        events.append(process_spawn(host, noise_user, ts, rid))
        rid += 1

    # DNS queries
    for _ in range(noise_spec.dns_queries):
        ts = base_time + timedelta(seconds=random.randint(0, spread_seconds))
        events.append(dns_query(host, noise_user, ts, rid))
        rid += 1

    events.sort(key=lambda e: e.timestamp)
    return events
