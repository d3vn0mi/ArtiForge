"""WMI event generators (Microsoft-Windows-WMI-Activity/Operational).

EID 5857 — WMI Activity — provider loaded
EID 5860 — WMI Temporary Subscription created
EID 5861 — WMI Permanent Subscription created
"""

from __future__ import annotations

from typing import Any

from artiforge.core.models import Host, User


# ── EID 5857 — WMI Activity (Provider Loaded) ────────────────────────────────

def eid_5857(fields: dict, host: Host, **_) -> dict:
    return {
        "NamespaceName": fields.get("NamespaceName", "root\\cimv2"),
        "ProviderName": fields.get("ProviderName", "WmiPerfClass"),
        "ProviderGuid": fields.get("ProviderGuid", "{AA3F95BD-5A8A-4739-9F44-01D5CF419B5B}"),
        "HostProcess": fields.get("HostProcess",
            r"wmiprvse.exe (PID: 4012, ProviderHostQuotaConfiguration)"),
        "ProcessID": fields.get("ProcessID", "4012"),
        "User": fields.get("User", "NT AUTHORITY\\NETWORK SERVICE"),
        "Code": fields.get("Code", "0x0"),
        "PossibleCause": fields.get("PossibleCause", ""),
    }


# ── EID 5860 — WMI Temporary Subscription ────────────────────────────────────

def eid_5860(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "NamespaceName": fields.get("NamespaceName", "root\\subscription"),
        "ConsumerName": fields.get("ConsumerName",
            'NTEventLogEventConsumer.Name="SCM Event Log Consumer"'),
        "ConsumerType": fields.get("ConsumerType", "NTEventLogEventConsumer"),
        "Query": fields.get("Query",
            "SELECT * FROM MSFT_WMI_GenericNonCOMEvent WHERE PropName = 'EventCode' AND PropValue = 7045"),
        "EventNamespace": fields.get("EventNamespace", "root\\cimv2"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
        "IsNotQuery": fields.get("IsNotQuery", "False"),
        "PossibleCause": fields.get("PossibleCause", ""),
    }


# ── EID 5861 — WMI Permanent Subscription ────────────────────────────────────

def eid_5861(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "NamespaceName": fields.get("NamespaceName", "root\\subscription"),
        "ConsumerName": fields.get("ConsumerName",
            'CommandLineEventConsumer.Name="EvilConsumer"'),
        "ConsumerType": fields.get("ConsumerType", "CommandLineEventConsumer"),
        "Query": fields.get("Query",
            "SELECT * FROM __InstanceCreationEvent WITHIN 5 "
            "WHERE TargetInstance ISA 'Win32_Process'"),
        "EventNamespace": fields.get("EventNamespace", "root\\cimv2"),
        "Name": fields.get("Name", "EvilConsumer"),
        "ConsumerPath": fields.get("ConsumerPath",
            r"C:\Windows\System32\cmd.exe /c C:\Temp\evil.exe"),
        "User": fields.get("User", f"{user.domain}\\{user.username}" if user else "NT AUTHORITY\\SYSTEM"),
        "PossibleCause": fields.get("PossibleCause", ""),
    }


# ── Dispatcher ────────────────────────────────────────────────────────────────

_GENERATORS = {
    5857: eid_5857,
    5860: eid_5860,
    5861: eid_5861,
}


def generate(eid: int, fields: dict, host: Host, user: User | None,
             spec: Any, timestamp: Any) -> dict:
    fn = _GENERATORS.get(eid)
    if fn is None:
        raise ValueError(f"WMI EID {eid} not implemented.")
    return fn(fields=fields, host=host, user=user, spec=spec, timestamp=timestamp)
