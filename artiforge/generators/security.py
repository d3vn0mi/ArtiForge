"""Windows Security channel event generators.

Each function takes the raw fields dict from the YAML, plus resolved context,
and returns a fully-populated event_data dict for GeneratedEvent.
"""

from __future__ import annotations

import random
import string
from datetime import datetime
from typing import Any

from artiforge.core.models import Host, User


def _hex(n: int | None = None) -> str:
    if n is None:
        n = random.randint(0x1000, 0xFFFF)
    return f"0x{n:x}"


def _logon_id() -> str:
    return _hex(random.randint(0x100000, 0xFFFFFF))


def _pid() -> str:
    return str(random.randint(1000, 15000))


def _new_logon_guid() -> str:
    import uuid
    return "{" + str(uuid.uuid4()).upper() + "}"


def _null_guid() -> str:
    return "{00000000-0000-0000-0000-000000000000}"


def _sid(host: Host, user: User | None) -> str:
    if user:
        return host.user_sid(user.rid)
    return "S-1-5-18"  # SYSTEM


# ── EID 4624 — Successful Logon ───────────────────────────────────────────────

def eid_4624(fields: dict, host: Host, user: User | None, **_) -> dict:
    logon_type = str(fields.get("LogonType", "3"))
    return {
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": "-",
        "SubjectDomainName": "-",
        "SubjectLogonId": _logon_id(),
        "TargetUserSid": _sid(host, user),
        "TargetUserName": fields.get("TargetUserName", user.username if user else "-"),
        "TargetDomainName": fields.get("TargetDomainName", user.domain if user else "-"),
        "TargetLogonId": _logon_id(),
        "LogonType": logon_type,
        "LogonProcessName": fields.get("LogonProcessName", "User32" if logon_type == "10" else "NtLmSsp"),
        "AuthenticationPackageName": fields.get("AuthenticationPackageName", "Negotiate"),
        "WorkstationName": fields.get("WorkstationName", host.name),
        "LogonGuid": fields.get("LogonGuid",
            _null_guid() if fields.get("AuthenticationPackageName") == "NTLM"
            else _new_logon_guid()),
        "TransmittedServices": "-",
        "LmPackageName": "-",
        "KeyLength": "0",
        "ProcessId": _pid(),
        "ProcessName": fields.get("ProcessName", r"C:\Windows\System32\winlogon.exe"),
        "IpAddress": fields.get("IpAddress", "-"),
        "IpPort": fields.get("IpPort", "-"),
        "ImpersonationLevel": "%%1833",
        "RestrictedAdminMode": "-",
        "RemoteCredentialGuard": "-",
        "TargetOutboundUserName": "-",
        "TargetOutboundDomainName": "-",
        "VirtualAccount": "%%1843",
        "TargetLinkedLogonId": "0x0",
        "ElevatedToken": "%%1842",
    }


# ── EID 4625 — Failed Logon ───────────────────────────────────────────────────

def eid_4625(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "SubjectUserSid": "S-1-0-0",
        "SubjectUserName": "-",
        "SubjectDomainName": "-",
        "SubjectLogonId": "0x0",
        "TargetUserSid": "S-1-0-0",
        "TargetUserName": fields.get("TargetUserName", user.username if user else "unknown"),
        "TargetDomainName": fields.get("TargetDomainName", user.domain if user else "-"),
        "Status": fields.get("Status", "0xc000006d"),
        "FailureReason": "%%2313",
        "SubStatus": fields.get("SubStatus", "0xc000006a"),
        "LogonType": str(fields.get("LogonType", "3")),
        "LogonProcessName": "NtLmSsp",
        "AuthenticationPackageName": "NTLM",
        "WorkstationName": fields.get("WorkstationName", host.name),
        "TransmittedServices": "-",
        "LmPackageName": "-",
        "KeyLength": "0",
        "ProcessId": "0x0",
        "ProcessName": "-",
        "IpAddress": fields.get("IpAddress", "-"),
        "IpPort": fields.get("IpPort", "-"),
    }


# ── EID 4634 — Logoff ─────────────────────────────────────────────────────────

def eid_4634(fields: dict, user: User | None, **_) -> dict:
    return {
        "TargetUserSid": fields.get("TargetUserSid", "S-1-5-21-xxx"),
        "TargetUserName": fields.get("TargetUserName", user.username if user else "-"),
        "TargetDomainName": fields.get("TargetDomainName", user.domain if user else "-"),
        "TargetLogonId": _logon_id(),
        "LogonType": str(fields.get("LogonType", "10")),
    }


# ── EID 4648 — Explicit Credentials Logon ────────────────────────────────────

def eid_4648(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "-"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "-"),
        "SubjectLogonId": _logon_id(),
        "LogonGuid": fields.get("LogonGuid", _new_logon_guid()),
        "TargetUserName": fields.get("TargetUserName", "svc_backup_admin"),
        "TargetDomainName": fields.get("TargetDomainName", host.name),
        "TargetLogonGuid": "{00000000-0000-0000-0000-000000000000}",
        "TargetServerName": fields.get("TargetServerName", "-"),
        "TargetInfo": fields.get("TargetInfo", "-"),
        "ProcessId": _pid(),
        "ProcessName": fields.get("ProcessName", r"C:\Windows\System32\mstsc.exe"),
        "IpAddress": fields.get("IpAddress", host.ip),
        "IpPort": fields.get("IpPort", "0"),
    }


# ── EID 4688 — Process Creation ───────────────────────────────────────────────

def eid_4688(fields: dict, host: Host, user: User | None, **_) -> dict:
    subject_user = fields.get("SubjectUserName", user.username if user else "SYSTEM")
    subject_domain = fields.get("SubjectDomainName", user.domain if user else "NT AUTHORITY")
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": subject_user,
        "SubjectDomainName": subject_domain,
        "SubjectLogonId": _logon_id(),
        "NewProcessId": _pid(),
        "NewProcessName": fields.get("NewProcessName", r"C:\Windows\System32\cmd.exe"),
        "TokenElevationType": fields.get("TokenElevationType", "%%1938"),
        "ProcessId": _pid(),
        "CommandLine": fields.get("CommandLine", ""),
        "TargetUserSid": "S-1-0-0",
        "TargetUserName": "-",
        "TargetDomainName": "-",
        "TargetLogonId": "0x0",
        "ParentProcessName": fields.get("ParentProcessName", r"C:\Windows\System32\cmd.exe"),
        "MandatoryLabel": "S-1-16-8192",
    }


# ── EID 4698 — Scheduled Task Created ────────────────────────────────────────

def eid_4698(fields: dict, host: Host, user: User | None, **_) -> dict:
    task_name = fields.get("TaskName", r"\MicrosoftEdgeUpdateTaskMachineUA")
    task_content = fields.get("TaskContent", _default_task_xml(task_name))
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "SYSTEM"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "NT AUTHORITY"),
        "SubjectLogonId": _logon_id(),
        "TaskName": task_name,
        "TaskContent": task_content,
    }


def _default_task_xml(task_name: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        f'<RegistrationInfo><Description>{task_name}</Description></RegistrationInfo>'
        '<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>'
        '<Actions><Exec><Command>cmd.exe</Command>'
        '<Arguments>/c echo persistence_check</Arguments></Exec></Actions>'
        '</Task>'
    )


# ── EID 4720 — User Account Created ──────────────────────────────────────────

def eid_4720(fields: dict, host: Host, user: User | None, spec: Any, **_) -> dict:
    new_account = fields.get("TargetUserName", spec.attack.malicious_account)
    return {
        "TargetUserName": new_account,
        "TargetDomainName": fields.get("TargetDomainName", host.name),
        "TargetSid": fields.get("TargetSid", f"{host.sid_prefix}-1100"),
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "SYSTEM"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "NT AUTHORITY"),
        "SubjectLogonId": _logon_id(),
        "PrivilegeList": "-",
        "SamAccountName": new_account,
        "DisplayName": "%%1793",
        "UserPrincipalName": "-",
        "HomeDirectory": "%%1793",
        "HomePath": "%%1793",
        "ScriptPath": "%%1793",
        "ProfilePath": "%%1793",
        "UserWorkstations": "%%1793",
        "PasswordLastSet": "%%1794",
        "AccountExpires": "%%1794",
        "PrimaryGroupId": "513",
        "AllowedToDelegateTo": "-",
        "OldUacValue": "0x0",
        "NewUacValue": "0x15",
        "UserAccountControl": "%%2080\n\t\t%%2082\n\t\t%%2084",
        "UserParameters": "%%1793",
        "SidHistory": "-",
        "LogonHours": "%%1797",
    }


# ── EID 4732 — Member Added to Security-Enabled Local Group ──────────────────

def eid_4732(fields: dict, host: Host, user: User | None, spec: Any, **_) -> dict:
    new_account = fields.get("MemberName", spec.attack.malicious_account)
    return {
        "MemberSid": fields.get("MemberSid", f"{host.sid_prefix}-1100"),
        "MemberName": f"{host.name}\\{new_account}",
        "TargetUserName": fields.get("TargetUserName", "Administrators"),
        "TargetDomainName": fields.get("TargetDomainName", host.name),
        "TargetSid": "S-1-5-32-544",
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "SYSTEM"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "NT AUTHORITY"),
        "SubjectLogonId": _logon_id(),
        "PrivilegeList": "-",
    }


# ── EID 4776 — Credential Validation (NTLM) ──────────────────────────────────

def eid_4776(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "PackageName": fields.get("PackageName", "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"),
        "LogonAccount": fields.get("LogonAccount", user.username if user else "-"),
        "Workstation": fields.get("Workstation", host.name),
        "Status": fields.get("Status", "0x0"),
    }


# ── EID 4768 — Kerberos TGT Requested ───────────────────────────────────────

def eid_4768(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "TargetUserName": fields.get("TargetUserName", user.username if user else "-"),
        "TargetDomainName": fields.get("TargetDomainName", user.domain if user else "-"),
        "TargetSid": _sid(host, user),
        "ServiceName": fields.get("ServiceName", "krbtgt"),
        "ServiceSid": fields.get("ServiceSid", "S-1-5-21-xxx-502"),
        "TicketOptions": fields.get("TicketOptions", "0x40810010"),
        "Status": fields.get("Status", "0x0"),
        "TicketEncryptionType": fields.get("TicketEncryptionType", "0x12"),
        "PreAuthType": fields.get("PreAuthType", "15"),
        "IpAddress": fields.get("IpAddress", f"::{host.ip}"),
        "IpPort": fields.get("IpPort", str(random.randint(49152, 65535))),
        "CertIssuerName": "-",
        "CertSerialNumber": "-",
        "CertThumbprint": "-",
    }


# ── EID 4769 — Kerberos Service Ticket Requested ─────────────────────────────

def eid_4769(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "TargetUserName": fields.get("TargetUserName",
            f"{user.username}@{user.domain}" if user else "-"),
        "TargetDomainName": fields.get("TargetDomainName", user.domain if user else "-"),
        "ServiceName": fields.get("ServiceName", "cifs/WIN-FS1"),
        "ServiceSid": fields.get("ServiceSid", "S-1-5-21-xxx-1103"),
        "TicketOptions": fields.get("TicketOptions", "0x40810000"),
        "TicketEncryptionType": fields.get("TicketEncryptionType", "0x12"),
        "IpAddress": fields.get("IpAddress", f"::{host.ip}"),
        "IpPort": fields.get("IpPort", str(random.randint(49152, 65535))),
        "Status": fields.get("Status", "0x0"),
        "LogonGuid": _new_logon_guid(),
        "TransmittedServices": "-",
    }


# ── EID 4771 — Kerberos Pre-Authentication Failed ────────────────────────────

def eid_4771(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "TargetUserName": fields.get("TargetUserName", user.username if user else "-"),
        "TargetSid": _sid(host, user),
        "ServiceName": fields.get("ServiceName", "krbtgt/LAB"),
        "TicketOptions": fields.get("TicketOptions", "0x40810010"),
        "Status": fields.get("Status", "0x18"),
        "PreAuthType": fields.get("PreAuthType", "2"),
        "IpAddress": fields.get("IpAddress", f"::{host.ip}"),
        "IpPort": fields.get("IpPort", str(random.randint(49152, 65535))),
        "CertIssuerName": "-",
        "CertSerialNumber": "-",
        "CertThumbprint": "-",
    }


# ── EID 4723 — Password Change Attempted ─────────────────────────────────────

def eid_4723(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "-"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "-"),
        "SubjectLogonId": _logon_id(),
        "TargetUserName": fields.get("TargetUserName", user.username if user else "-"),
        "TargetDomainName": fields.get("TargetDomainName", user.domain if user else "-"),
        "TargetSid": _sid(host, user),
    }


# ── EID 4724 — Password Reset ─────────────────────────────────────────────────

def eid_4724(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "SYSTEM"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "NT AUTHORITY"),
        "SubjectLogonId": _logon_id(),
        "TargetUserName": fields.get("TargetUserName", "svc_backup_admin"),
        "TargetDomainName": fields.get("TargetDomainName", host.name),
        "TargetSid": fields.get("TargetSid", f"{host.sid_prefix}-1100"),
    }


# ── EID 4725 — User Account Disabled ─────────────────────────────────────────

def eid_4725(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "SYSTEM"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "NT AUTHORITY"),
        "SubjectLogonId": _logon_id(),
        "TargetUserName": fields.get("TargetUserName", "victim.user"),
        "TargetDomainName": fields.get("TargetDomainName", host.name),
        "TargetSid": fields.get("TargetSid", f"{host.sid_prefix}-1101"),
    }


# ── EID 4726 — User Account Deleted ──────────────────────────────────────────

def eid_4726(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "SYSTEM"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "NT AUTHORITY"),
        "SubjectLogonId": _logon_id(),
        "TargetUserName": fields.get("TargetUserName", "victim.user"),
        "TargetDomainName": fields.get("TargetDomainName", host.name),
        "TargetSid": fields.get("TargetSid", f"{host.sid_prefix}-1101"),
        "PrivilegeList": "-",
        "SamAccountName": fields.get("TargetUserName", "victim.user"),
        "DisplayName": "%%1793",
        "UserPrincipalName": "-",
        "HomeDirectory": "%%1793",
        "HomePath": "%%1793",
        "ScriptPath": "%%1793",
        "ProfilePath": "%%1793",
        "UserWorkstations": "%%1793",
        "PasswordLastSet": "%%1794",
        "AccountExpires": "%%1794",
        "PrimaryGroupId": "513",
        "AllowedToDelegateTo": "-",
        "OldUacValue": "0x15",
        "NewUacValue": "0x11",
        "UserAccountControl": "%%2080",
        "UserParameters": "%%1793",
        "SidHistory": "-",
        "LogonHours": "%%1797",
    }


# ── EID 4656 — Handle to Object Requested ────────────────────────────────────

def eid_4656(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "-"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "-"),
        "SubjectLogonId": _logon_id(),
        "ObjectServer": fields.get("ObjectServer", "Security"),
        "ObjectType": fields.get("ObjectType", "File"),
        "ObjectName": fields.get("ObjectName", r"C:\Windows\System32\lsass.exe"),
        "HandleId": _hex(),
        "TransactionId": _null_guid(),
        "AccessList": fields.get("AccessList", "%%4416"),
        "AccessReason": fields.get("AccessReason", "%%4416: %%1801"),
        "AccessMask": fields.get("AccessMask", "0x1"),
        "PrivilegeList": "-",
        "RestrictedSidCount": "0",
        "ProcessId": _pid(),
        "ProcessName": fields.get("ProcessName", r"C:\Windows\System32\cmd.exe"),
        "ResourceAttributes": "-",
    }


# ── EID 4663 — Object Access ──────────────────────────────────────────────────

def eid_4663(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "-"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "-"),
        "SubjectLogonId": _logon_id(),
        "ObjectServer": fields.get("ObjectServer", "Security"),
        "ObjectType": fields.get("ObjectType", "File"),
        "ObjectName": fields.get("ObjectName", r"C:\Windows\System32\lsass.DMP"),
        "HandleId": _hex(),
        "AccessList": fields.get("AccessList", "%%4417"),
        "AccessMask": fields.get("AccessMask", "0x2"),
        "ProcessId": _pid(),
        "ProcessName": fields.get("ProcessName", r"C:\Windows\System32\cmd.exe"),
        "ResourceAttributes": "-",
        "TransactionId": _null_guid(),
    }


# ── EID 4657 — Registry Value Modified ───────────────────────────────────────

def eid_4657(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "-"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "-"),
        "SubjectLogonId": _logon_id(),
        "ObjectName": fields.get("ObjectName",
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        "ObjectValueName": fields.get("ObjectValueName", "Updater"),
        "HandleId": _hex(),
        "OperationType": fields.get("OperationType", "%%1904"),
        "OldValueType": fields.get("OldValueType", "%%1873"),
        "OldValue": fields.get("OldValue", "-"),
        "NewValueType": fields.get("NewValueType", "%%1873"),
        "NewValue": fields.get("NewValue", r"C:\ProgramData\update.exe"),
        "ProcessId": _pid(),
        "ProcessName": fields.get("ProcessName", r"C:\Windows\System32\reg.exe"),
    }


# ── EID 4670 — Permissions on Object Changed ─────────────────────────────────

def eid_4670(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "-"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "-"),
        "SubjectLogonId": _logon_id(),
        "ObjectServer": fields.get("ObjectServer", "Security"),
        "ObjectType": fields.get("ObjectType", "File"),
        "ObjectName": fields.get("ObjectName", r"C:\ProgramData\update.exe"),
        "HandleId": _hex(),
        "OldSd": fields.get("OldSd", "D:PAI(A;;FA;;;BA)"),
        "NewSd": fields.get("NewSd", "D:PAI(A;;FA;;;BA)(A;;FA;;;WD)"),
        "ProcessId": _pid(),
        "ProcessName": fields.get("ProcessName", r"C:\Windows\System32\icacls.exe"),
    }


# ── EID 5156 — WFP Connection Allowed ────────────────────────────────────────

def eid_5156(fields: dict, host: Host, **_) -> dict:
    return {
        "ProcessID": _pid(),
        "Application": fields.get("Application",
            r"\device\harddiskvolume3\windows\system32\svchost.exe"),
        "Direction": fields.get("Direction", "%%14593"),
        "SourceAddress": fields.get("SourceAddress", host.ip),
        "SourcePort": str(fields.get("SourcePort", random.randint(49152, 65535))),
        "DestAddress": fields.get("DestAddress", "8.8.8.8"),
        "DestPort": str(fields.get("DestPort", "443")),
        "Protocol": str(fields.get("Protocol", "6")),
        "FilterRTID": str(random.randint(60000, 99999)),
        "LayerName": "%%14610",
        "LayerRTID": "48",
        "RemoteUserID": "S-1-0-0",
        "RemoteMachineID": "S-1-0-0",
    }


# ── EID 5157 — WFP Connection Blocked ────────────────────────────────────────

def eid_5157(fields: dict, host: Host, **_) -> dict:
    return {
        "ProcessID": _pid(),
        "Application": fields.get("Application",
            r"\device\harddiskvolume3\programdata\microsoft\windows\update.exe"),
        "Direction": fields.get("Direction", "%%14593"),
        "SourceAddress": fields.get("SourceAddress", host.ip),
        "SourcePort": str(fields.get("SourcePort", random.randint(49152, 65535))),
        "DestAddress": fields.get("DestAddress", "198.41.192.227"),
        "DestPort": str(fields.get("DestPort", "443")),
        "Protocol": str(fields.get("Protocol", "6")),
        "FilterRTID": str(random.randint(60000, 99999)),
        "LayerName": "%%14610",
        "LayerRTID": "48",
        "RemoteUserID": "S-1-0-0",
        "RemoteMachineID": "S-1-0-0",
    }


# ── EID 4946 — Firewall Rule Added ───────────────────────────────────────────

def eid_4946(fields: dict, **_) -> dict:
    return {
        "ProfileChanged": fields.get("ProfileChanged", "All"),
        "AddedNewRule": fields.get("AddedNewRule", ""),
        "RuleId": fields.get("RuleId", _new_logon_guid()),
        "RuleName": fields.get("RuleName", "Allow Outbound Update"),
        "Origin": fields.get("Origin", "Local"),
        "ApplicationPath": fields.get("ApplicationPath",
            r"C:\ProgramData\Microsoft\Windows\update.exe"),
        "ServiceName": fields.get("ServiceName", ""),
        "Direction": fields.get("Direction", "Outbound"),
        "Protocol": fields.get("Protocol", "TCP"),
        "LocalPorts": fields.get("LocalPorts", "Any"),
        "RemotePorts": fields.get("RemotePorts", "443"),
        "LocalAddresses": fields.get("LocalAddresses", "Any"),
        "RemoteAddresses": fields.get("RemoteAddresses", "Any"),
        "RemoteMachineAuthorizationList": "",
        "RemoteUserAuthorizationList": "",
        "EmbeddedContext": "",
        "Active": "Yes",
        "Action": fields.get("Action", "Allow"),
        "EdgeTraversal": fields.get("EdgeTraversal", "No"),
        "LooseSourceMapped": "No",
        "SecurityOptions": "None",
        "ModifyingApplication": fields.get("ModifyingApplication",
            r"C:\Windows\System32\netsh.exe"),
    }


# ── EID 4947 — Firewall Rule Modified ────────────────────────────────────────

def eid_4947(fields: dict, **_) -> dict:
    return {
        "ProfileChanged": fields.get("ProfileChanged", "All"),
        "RuleId": fields.get("RuleId", _new_logon_guid()),
        "RuleName": fields.get("RuleName", "Allow Outbound Update"),
        "Origin": fields.get("Origin", "Local"),
        "ApplicationPath": fields.get("ApplicationPath",
            r"C:\ProgramData\Microsoft\Windows\update.exe"),
        "ServiceName": fields.get("ServiceName", ""),
        "ModifyingApplication": fields.get("ModifyingApplication",
            r"C:\Windows\System32\netsh.exe"),
    }


# ── EID 4672 — Special Privileges Assigned to New Logon ──────────────────────

def eid_4672(fields: dict, host: Host, user: User | None, **_) -> dict:
    return {
        "SubjectUserSid": _sid(host, user),
        "SubjectUserName": fields.get("SubjectUserName", user.username if user else "SYSTEM"),
        "SubjectDomainName": fields.get("SubjectDomainName", user.domain if user else "NT AUTHORITY"),
        "SubjectLogonId": _logon_id(),
        "PrivilegeList": fields.get("PrivilegeList", (
            "SeSecurityPrivilege\n\t\t\t\t"
            "SeTakeOwnershipPrivilege\n\t\t\t\t"
            "SeLoadDriverPrivilege\n\t\t\t\t"
            "SeBackupPrivilege\n\t\t\t\t"
            "SeRestorePrivilege\n\t\t\t\t"
            "SeDebugPrivilege\n\t\t\t\t"
            "SeSystemEnvironmentPrivilege\n\t\t\t\t"
            "SeImpersonatePrivilege\n\t\t\t\t"
            "SeDelegateSessionUserImpersonatePrivilege"
        )),
    }


# ── Dispatcher ────────────────────────────────────────────────────────────────

_GENERATORS = {
    # Authentication / Logon
    4624: eid_4624,
    4625: eid_4625,
    4634: eid_4634,
    4648: eid_4648,
    4672: eid_4672,
    4776: eid_4776,
    # Kerberos
    4768: eid_4768,
    4769: eid_4769,
    4771: eid_4771,
    # Process
    4688: eid_4688,
    # Scheduled Tasks
    4698: eid_4698,
    # Account management
    4720: eid_4720,
    4723: eid_4723,
    4724: eid_4724,
    4725: eid_4725,
    4726: eid_4726,
    4732: eid_4732,
    # Object access / handles
    4656: eid_4656,
    4663: eid_4663,
    4657: eid_4657,
    4670: eid_4670,
    # Windows Filtering Platform
    5156: eid_5156,
    5157: eid_5157,
    # Firewall
    4946: eid_4946,
    4947: eid_4947,
}


def generate(eid: int, fields: dict, host: Host, user: User | None,
             spec: Any, timestamp: Any) -> dict:
    fn = _GENERATORS.get(eid)
    if fn is None:
        raise ValueError(f"Security EID {eid} not implemented.")
    return fn(fields=fields, host=host, user=user, spec=spec, timestamp=timestamp)
