"""Tests for individual event generators — required fields, correct values."""

import pytest
from datetime import datetime, timezone
from artiforge.core.models import Host, User
from artiforge.generators import security, system, sysmon, application, powershell, wmi


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def host():
    return Host(
        name="WIN-WS1",
        ip="10.10.10.10",
        fqdn="WIN-WS1.lab.local",
        os="Windows 10 22H2",
        sid_prefix="S-1-5-21-111-222-333",
        users=[],
    )


@pytest.fixture
def user():
    return User(username="marcus.webb", domain="LAB", rid=1001)


@pytest.fixture
def ts():
    return datetime(2026, 2, 19, 9, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def spec_stub():
    """Minimal spec-like object with malicious_account."""
    class _Attack:
        malicious_account = "svc_backup_admin"
    class _Spec:
        attack = _Attack()
    return _Spec()


# ── Security EID 4688 ─────────────────────────────────────────────────────────

def test_4688_required_fields(host, user, ts, spec_stub):
    result = security.generate(4688, {
        "NewProcessName": r"C:\Windows\System32\ie4uinit.exe",
        "CommandLine": "ie4uinit.exe -BaseSettings",
        "ParentProcessName": r"C:\Windows\explorer.exe",
    }, host, user, spec_stub, ts)
    assert result["NewProcessName"] == r"C:\Windows\System32\ie4uinit.exe"
    assert result["CommandLine"] == "ie4uinit.exe -BaseSettings"
    assert result["ParentProcessName"] == r"C:\Windows\explorer.exe"
    assert result["SubjectUserName"] == "marcus.webb"
    assert result["SubjectDomainName"] == "LAB"


def test_4688_subject_from_user(host, user, ts, spec_stub):
    result = security.generate(4688, {}, host, user, spec_stub, ts)
    assert result["SubjectUserName"] == "marcus.webb"


def test_4688_default_process_if_no_fields(host, user, ts, spec_stub):
    result = security.generate(4688, {}, host, user, spec_stub, ts)
    assert "NewProcessName" in result
    assert "CommandLine" in result


# ── Security EID 4624 ─────────────────────────────────────────────────────────

def test_4624_logon_type_10(host, user, ts, spec_stub):
    result = security.generate(4624, {"LogonType": "10", "IpAddress": "10.10.10.10"},
                                host, user, spec_stub, ts)
    assert result["LogonType"] == "10"
    assert result["IpAddress"] == "10.10.10.10"


def test_4624_has_required_keys(host, user, ts, spec_stub):
    result = security.generate(4624, {}, host, user, spec_stub, ts)
    for key in ["LogonType", "AuthenticationPackageName", "LogonProcessName",
                "TargetUserName", "TargetDomainName"]:
        assert key in result


# ── Security EID 4648 ─────────────────────────────────────────────────────────

def test_4648_explicit_creds(host, user, ts, spec_stub):
    result = security.generate(4648, {
        "TargetUserName": "svc_backup_admin",
        "TargetServerName": "WIN-BACKUP1",
        "IpAddress": "10.10.10.10",
    }, host, user, spec_stub, ts)
    assert result["TargetUserName"] == "svc_backup_admin"
    assert result["IpAddress"] == "10.10.10.10"


# ── Security EID 4698 ─────────────────────────────────────────────────────────

def test_4698_task_fields(host, user, ts, spec_stub):
    result = security.generate(4698, {
        "TaskName": r"\MicrosoftEdgeUpdateTaskMachineUA",
    }, host, user, spec_stub, ts)
    assert "MicrosoftEdgeUpdateTaskMachineUA" in result["TaskName"]
    assert "TaskContent" in result
    assert "<Task" in result["TaskContent"]


# ── Security EID 4720 ─────────────────────────────────────────────────────────

def test_4720_new_account(host, user, ts, spec_stub):
    result = security.generate(4720, {}, host, user, spec_stub, ts)
    assert result["TargetUserName"] == "svc_backup_admin"
    assert "SamAccountName" in result


# ── Security EID 4732 ─────────────────────────────────────────────────────────

def test_4732_administrators(host, user, ts, spec_stub):
    result = security.generate(4732, {}, host, user, spec_stub, ts)
    assert result["TargetUserName"] == "Administrators"
    assert result["TargetSid"] == "S-1-5-32-544"
    assert "svc_backup_admin" in result["MemberName"]


# ── Security EID 4634 ─────────────────────────────────────────────────────────

def test_4634_logoff(host, user, ts, spec_stub):
    result = security.generate(4634, {"LogonType": "10"}, host, user, spec_stub, ts)
    assert result["LogonType"] == "10"


# ── System EID 7045 ──────────────────────────────────────────────────────────

def test_7045_service_fields(host, user, ts, spec_stub):
    result = system.generate(7045, {
        "ServiceName": "Wuauserv_Svc",
        "ImagePath": r"C:\ProgramData\Microsoft\Windows\update.exe tunnel run --token FAKE_TOKEN",
    }, host, user, spec_stub, ts)
    assert result["ServiceName"] == "Wuauserv_Svc"
    assert "update.exe" in result["ImagePath"]
    assert result["StartType"] == "auto start"


def test_7045_defaults(host, user, ts, spec_stub):
    result = system.generate(7045, {}, host, user, spec_stub, ts)
    assert result["ServiceName"] == "Wuauserv_Svc"
    assert "FAKE_TOKEN" in result["ImagePath"]


# ── Sysmon EID 1 ─────────────────────────────────────────────────────────────

def test_sysmon1_process_fields(host, user, ts, spec_stub):
    result = sysmon.generate(1, {
        "Image": r"C:\Windows\System32\ie4uinit.exe",
        "CommandLine": "ie4uinit.exe -BaseSettings",
        "ParentImage": r"C:\Windows\explorer.exe",
    }, host, user, spec_stub, ts)
    assert result["Image"] == r"C:\Windows\System32\ie4uinit.exe"
    assert result["CommandLine"] == "ie4uinit.exe -BaseSettings"
    assert result["ParentImage"] == r"C:\Windows\explorer.exe"
    assert result["User"] == "LAB\\marcus.webb"


def test_sysmon1_has_hash(host, user, ts, spec_stub):
    result = sysmon.generate(1, {}, host, user, spec_stub, ts)
    assert "Hashes" in result
    assert "SHA256=" in result["Hashes"]


def test_sysmon1_guids_are_unique(host, user, ts, spec_stub):
    r1 = sysmon.generate(1, {}, host, user, spec_stub, ts)
    r2 = sysmon.generate(1, {}, host, user, spec_stub, ts)
    assert r1["ProcessGuid"] != r2["ProcessGuid"]


# ── Sysmon EID 3 ─────────────────────────────────────────────────────────────

def test_sysmon3_network_fields(host, user, ts, spec_stub):
    result = sysmon.generate(3, {
        "Image": r"C:\ProgramData\Microsoft\Windows\update.exe",
        "DestinationIp": "198.41.192.227",
        "DestinationPort": 443,
        "DestinationHostname": "region2.v2.argotunnel.com",
    }, host, user, spec_stub, ts)
    assert result["DestinationIp"] == "198.41.192.227"
    assert result["DestinationPort"] == "443"
    assert result["DestinationHostname"] == "region2.v2.argotunnel.com"
    assert result["SourceIp"] == "10.10.10.10"   # from host fixture


# ── Sysmon EID 11 ────────────────────────────────────────────────────────────

def test_sysmon11_file_create(host, user, ts, spec_stub):
    result = sysmon.generate(11, {
        "TargetFilename": r"C:\ProgramData\MicrosoftEdgeUpdate\update.txt",
    }, host, user, spec_stub, ts)
    assert result["TargetFilename"] == r"C:\ProgramData\MicrosoftEdgeUpdate\update.txt"
    assert "UtcTime" in result


# ── Sysmon EID 13 ────────────────────────────────────────────────────────────

def test_sysmon13_registry(host, user, ts, spec_stub):
    result = sysmon.generate(13, {
        "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule",
    }, host, user, spec_stub, ts)
    assert "HKLM" in result["TargetObject"]
    assert result["EventType"] == "SetValue"


# ── Application EID 1 ────────────────────────────────────────────────────────

def test_app1_cloudflared_error(host, user, ts, spec_stub):
    result = application.generate(1, {
        "Data": "ERR Failed to create tunnel error=connection timed out",
    }, host, user, spec_stub, ts)
    assert "ERR" in result["Data"]


def test_app1_default_data(host, user, ts, spec_stub):
    result = application.generate(1, {}, host, user, spec_stub, ts)
    assert "cloudflared" in result["Data"].lower() or "tunnel" in result["Data"].lower()


# ── Security EID 4776 ────────────────────────────────────────────────────────

def test_4776_ntlm_fields(host, user, ts, spec_stub):
    result = security.generate(4776, {
        "LogonAccount": "marcus.webb",
        "Workstation": "WIN-WS1",
        "Status": "0x0",
    }, host, user, spec_stub, ts)
    assert result["LogonAccount"] == "marcus.webb"
    assert result["Workstation"] == "WIN-WS1"
    assert result["Status"] == "0x0"
    assert "PackageName" in result


# ── System EID 7036 ───────────────────────────────────────────────────────────

def test_7036_service_state(host, user, ts, spec_stub):
    result = system.generate(7036, {
        "param1": "Wuauserv_Svc",
        "param2": "running",
    }, host, user, spec_stub, ts)
    assert result["param1"] == "Wuauserv_Svc"
    assert result["param2"] == "running"


# ── Sysmon EID 22 ────────────────────────────────────────────────────────────

def test_sysmon22_dns_query(host, user, ts, spec_stub):
    result = sysmon.generate(22, {
        "QueryName": "region2.v2.argotunnel.com",
        "Image": r"C:\ProgramData\Microsoft\Windows\update.exe",
    }, host, user, spec_stub, ts)
    assert result["QueryName"] == "region2.v2.argotunnel.com"
    assert result["Image"] == r"C:\ProgramData\Microsoft\Windows\update.exe"
    assert "QueryResults" in result
    assert "UtcTime" in result


# ── PowerShell EID 4103 ───────────────────────────────────────────────────────

def test_4103_module_logging(host, user, ts, spec_stub):
    result = powershell.generate(4103, {
        "CommandName": "Compress-Archive",
    }, host, user, spec_stub, ts)
    assert "Payload" in result
    assert "ContextInfo" in result
    assert "Compress-Archive" in result["ContextInfo"]


# ── PowerShell EID 4104 ───────────────────────────────────────────────────────

def test_4104_script_block(host, user, ts, spec_stub):
    result = powershell.generate(4104, {
        "ScriptBlockText": "Compress-Archive -Path C:\\Users\\* -DestinationPath C:\\Temp\\out.zip",
    }, host, user, spec_stub, ts)
    assert "Compress-Archive" in result["ScriptBlockText"]
    assert "ScriptBlockId" in result
    assert result["MessageNumber"] == "1"


def test_4104_defaults(host, user, ts, spec_stub):
    result = powershell.generate(4104, {}, host, user, spec_stub, ts)
    assert "ScriptBlockText" in result
    assert "ScriptBlockId" in result


def test_unknown_powershell_eid_raises(host, user, ts, spec_stub):
    with pytest.raises(ValueError, match="not implemented"):
        powershell.generate(9999, {}, host, user, spec_stub, ts)


# ── Sysmon 1 hash format now includes MD5 ────────────────────────────────────

def test_sysmon1_hashes_include_md5(host, user, ts, spec_stub):
    result = sysmon.generate(1, {}, host, user, spec_stub, ts)
    assert "MD5=" in result["Hashes"]
    assert "SHA256=" in result["Hashes"]


# ── Unknown EID raises ────────────────────────────────────────────────────────

def test_unknown_security_eid_raises(host, user, ts, spec_stub):
    with pytest.raises(ValueError, match="not implemented"):
        security.generate(9999, {}, host, user, spec_stub, ts)


def test_unknown_sysmon_eid_raises(host, user, ts, spec_stub):
    with pytest.raises(ValueError, match="not implemented"):
        sysmon.generate(999, {}, host, user, spec_stub, ts)


def test_unknown_system_eid_raises(host, user, ts, spec_stub):
    with pytest.raises(ValueError, match="not implemented"):
        system.generate(9999, {}, host, user, spec_stub, ts)


# ── Security EID 4768 — Kerberos TGT ─────────────────────────────────────────

def test_4768_tgt_fields(host, user, ts, spec_stub):
    result = security.generate(4768, {
        "TargetUserName": "marcus.webb",
        "Status": "0x0",
    }, host, user, spec_stub, ts)
    assert result["TargetUserName"] == "marcus.webb"
    assert result["Status"] == "0x0"
    assert result["ServiceName"] == "krbtgt"
    assert "TicketOptions" in result
    assert "TicketEncryptionType" in result


def test_4768_defaults(host, user, ts, spec_stub):
    result = security.generate(4768, {}, host, user, spec_stub, ts)
    assert result["TargetUserName"] == "marcus.webb"
    assert result["PreAuthType"] == "15"


# ── Security EID 4769 — Kerberos Service Ticket ───────────────────────────────

def test_4769_service_ticket(host, user, ts, spec_stub):
    result = security.generate(4769, {
        "ServiceName": "cifs/WIN-FS1",
        "Status": "0x0",
    }, host, user, spec_stub, ts)
    assert result["ServiceName"] == "cifs/WIN-FS1"
    assert result["Status"] == "0x0"
    assert "TicketOptions" in result


# ── Security EID 4771 — Kerberos Pre-auth Failed ─────────────────────────────

def test_4771_preauth_failed(host, user, ts, spec_stub):
    result = security.generate(4771, {
        "Status": "0x18",
        "PreAuthType": "2",
    }, host, user, spec_stub, ts)
    assert result["Status"] == "0x18"
    assert result["PreAuthType"] == "2"
    assert "TargetUserName" in result


# ── Security EID 4723/4724 — Password Change/Reset ───────────────────────────

def test_4723_password_change(host, user, ts, spec_stub):
    result = security.generate(4723, {
        "TargetUserName": "marcus.webb",
    }, host, user, spec_stub, ts)
    assert result["TargetUserName"] == "marcus.webb"
    assert "SubjectUserName" in result


def test_4724_password_reset(host, user, ts, spec_stub):
    result = security.generate(4724, {
        "TargetUserName": "svc_backup_admin",
    }, host, user, spec_stub, ts)
    assert result["TargetUserName"] == "svc_backup_admin"
    assert "TargetSid" in result


# ── Security EID 4725/4726 — Account Disabled/Deleted ────────────────────────

def test_4725_account_disabled(host, user, ts, spec_stub):
    result = security.generate(4725, {
        "TargetUserName": "victim.user",
    }, host, user, spec_stub, ts)
    assert result["TargetUserName"] == "victim.user"
    assert "SubjectUserName" in result


def test_4726_account_deleted(host, user, ts, spec_stub):
    result = security.generate(4726, {
        "TargetUserName": "victim.user",
    }, host, user, spec_stub, ts)
    assert result["TargetUserName"] == "victim.user"
    assert result["PrimaryGroupId"] == "513"


# ── Security EID 4656/4663 — Object Access ────────────────────────────────────

def test_4656_handle_request(host, user, ts, spec_stub):
    result = security.generate(4656, {
        "ObjectName": r"C:\Windows\System32\lsass.exe",
        "ObjectType": "File",
        "AccessMask": "0x1410",
    }, host, user, spec_stub, ts)
    assert result["ObjectName"] == r"C:\Windows\System32\lsass.exe"
    assert result["ObjectType"] == "File"
    assert result["AccessMask"] == "0x1410"
    assert "SubjectUserName" in result


def test_4663_object_access(host, user, ts, spec_stub):
    result = security.generate(4663, {
        "ObjectName": r"C:\Windows\System32\lsass.DMP",
        "ObjectType": "File",
    }, host, user, spec_stub, ts)
    assert result["ObjectName"] == r"C:\Windows\System32\lsass.DMP"
    assert "AccessList" in result
    assert "ProcessName" in result


# ── Security EID 4657 — Registry Modified ─────────────────────────────────────

def test_4657_registry_modified(host, user, ts, spec_stub):
    result = security.generate(4657, {
        "ObjectValueName": "Updater",
        "NewValue": r"C:\ProgramData\update.exe",
    }, host, user, spec_stub, ts)
    assert result["ObjectValueName"] == "Updater"
    assert result["NewValue"] == r"C:\ProgramData\update.exe"
    assert "ObjectName" in result


# ── Security EID 4670 — Permissions Changed ───────────────────────────────────

def test_4670_permissions_changed(host, user, ts, spec_stub):
    result = security.generate(4670, {
        "ObjectName": r"C:\ProgramData\update.exe",
    }, host, user, spec_stub, ts)
    assert result["ObjectName"] == r"C:\ProgramData\update.exe"
    assert "OldSd" in result
    assert "NewSd" in result


# ── Security EID 5156/5157 — WFP Allowed/Blocked ─────────────────────────────

def test_5156_wfp_allowed(host, user, ts, spec_stub):
    result = security.generate(5156, {
        "DestAddress": "8.8.8.8",
        "DestPort": "443",
    }, host, user, spec_stub, ts)
    assert result["DestAddress"] == "8.8.8.8"
    assert result["DestPort"] == "443"
    assert result["SourceAddress"] == "10.10.10.10"
    assert "ProcessID" in result


def test_5157_wfp_blocked(host, user, ts, spec_stub):
    result = security.generate(5157, {
        "DestAddress": "198.41.192.227",
    }, host, user, spec_stub, ts)
    assert result["DestAddress"] == "198.41.192.227"
    assert "ProcessID" in result


# ── Security EID 4946/4947 — Firewall Rules ───────────────────────────────────

def test_4946_firewall_rule_added(host, user, ts, spec_stub):
    result = security.generate(4946, {
        "RuleName": "Allow Outbound Update",
        "Direction": "Outbound",
    }, host, user, spec_stub, ts)
    assert result["RuleName"] == "Allow Outbound Update"
    assert result["Direction"] == "Outbound"
    assert "ApplicationPath" in result


def test_4947_firewall_rule_modified(host, user, ts, spec_stub):
    result = security.generate(4947, {
        "RuleName": "Allow Outbound Update",
    }, host, user, spec_stub, ts)
    assert result["RuleName"] == "Allow Outbound Update"
    assert "ModifyingApplication" in result


# ── Sysmon EID 5 — Process Terminated ────────────────────────────────────────

def test_sysmon5_process_terminated(host, user, ts, spec_stub):
    result = sysmon.generate(5, {
        "Image": r"C:\Windows\System32\cmd.exe",
    }, host, user, spec_stub, ts)
    assert result["Image"] == r"C:\Windows\System32\cmd.exe"
    assert "UtcTime" in result
    assert "ProcessGuid" in result


# ── Sysmon EID 7 — Image Loaded ──────────────────────────────────────────────

def test_sysmon7_image_loaded(host, user, ts, spec_stub):
    result = sysmon.generate(7, {
        "ImageLoaded": r"C:\Windows\System32\amsi.dll",
        "Signed": "true",
    }, host, user, spec_stub, ts)
    assert result["ImageLoaded"] == r"C:\Windows\System32\amsi.dll"
    assert result["Signed"] == "true"
    assert "Hashes" in result
    assert "Signature" in result


# ── Sysmon EID 8 — CreateRemoteThread ────────────────────────────────────────

def test_sysmon8_remote_thread(host, user, ts, spec_stub):
    result = sysmon.generate(8, {
        "SourceImage": r"C:\Windows\System32\cmd.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1fffff",
    }, host, user, spec_stub, ts)
    assert result["SourceImage"] == r"C:\Windows\System32\cmd.exe"
    assert result["TargetImage"] == r"C:\Windows\System32\lsass.exe"
    assert "NewThreadId" in result
    assert "StartAddress" in result


# ── Sysmon EID 10 — ProcessAccess ────────────────────────────────────────────

def test_sysmon10_process_access(host, user, ts, spec_stub):
    result = sysmon.generate(10, {
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1010",
    }, host, user, spec_stub, ts)
    assert result["TargetImage"] == r"C:\Windows\System32\lsass.exe"
    assert result["GrantedAccess"] == "0x1010"
    assert "CallTrace" in result
    assert "SourceUser" in result


# ── Sysmon EID 12/14 — Registry Create/Rename ────────────────────────────────

def test_sysmon12_registry_create(host, user, ts, spec_stub):
    result = sysmon.generate(12, {
        "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",
        "EventType": "CreateKey",
    }, host, user, spec_stub, ts)
    assert "HKLM" in result["TargetObject"]
    assert result["EventType"] == "CreateKey"


def test_sysmon14_registry_rename(host, user, ts, spec_stub):
    result = sysmon.generate(14, {
        "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",
        "NewName": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate",
    }, host, user, spec_stub, ts)
    assert "NewName" in result
    assert "WindowsUpdate" in result["NewName"]


# ── Sysmon EID 17/18 — Named Pipe ────────────────────────────────────────────

def test_sysmon17_pipe_created(host, user, ts, spec_stub):
    result = sysmon.generate(17, {
        "PipeName": r"\\.\pipe\MSSE-1234-server",
    }, host, user, spec_stub, ts)
    assert result["PipeName"] == r"\\.\pipe\MSSE-1234-server"
    assert result["EventType"] == "CreatePipe"


def test_sysmon18_pipe_connected(host, user, ts, spec_stub):
    result = sysmon.generate(18, {
        "PipeName": r"\\.\pipe\MSSE-1234-server",
    }, host, user, spec_stub, ts)
    assert result["PipeName"] == r"\\.\pipe\MSSE-1234-server"
    assert result["EventType"] == "ConnectPipe"


# ── Sysmon EID 23 — FileDelete ────────────────────────────────────────────────

def test_sysmon23_file_delete(host, user, ts, spec_stub):
    result = sysmon.generate(23, {
        "TargetFilename": r"C:\Temp\payload.exe",
        "IsExecutable": "true",
    }, host, user, spec_stub, ts)
    assert result["TargetFilename"] == r"C:\Temp\payload.exe"
    assert result["IsExecutable"] == "true"
    assert "Hashes" in result


# ── Sysmon EID 25 — ProcessTampering ─────────────────────────────────────────

def test_sysmon25_process_tampering(host, user, ts, spec_stub):
    result = sysmon.generate(25, {
        "Image": r"C:\Windows\System32\svchost.exe",
        "Type": "Image is locked for reading",
    }, host, user, spec_stub, ts)
    assert result["Image"] == r"C:\Windows\System32\svchost.exe"
    assert result["Type"] == "Image is locked for reading"
    assert "ProcessGuid" in result


# ── WMI EID 5857 — Provider Loaded ───────────────────────────────────────────

def test_wmi5857_provider_loaded(host, user, ts, spec_stub):
    result = wmi.generate(5857, {
        "ProviderName": "WmiPerfClass",
    }, host, user, spec_stub, ts)
    assert result["ProviderName"] == "WmiPerfClass"
    assert "NamespaceName" in result
    assert "HostProcess" in result


# ── WMI EID 5860 — Temporary Subscription ────────────────────────────────────

def test_wmi5860_temp_subscription(host, user, ts, spec_stub):
    result = wmi.generate(5860, {
        "ConsumerName": 'NTEventLogEventConsumer.Name="SCM Event Log Consumer"',
        "Query": "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_Process'",
    }, host, user, spec_stub, ts)
    assert "SCM Event Log" in result["ConsumerName"]
    assert "Win32_Process" in result["Query"]
    assert "NamespaceName" in result


# ── WMI EID 5861 — Permanent Subscription ────────────────────────────────────

def test_wmi5861_permanent_subscription(host, user, ts, spec_stub):
    result = wmi.generate(5861, {
        "ConsumerName": 'CommandLineEventConsumer.Name="EvilConsumer"',
        "ConsumerPath": r"C:\Windows\System32\cmd.exe /c C:\Temp\evil.exe",
    }, host, user, spec_stub, ts)
    assert "EvilConsumer" in result["ConsumerName"]
    assert "evil.exe" in result["ConsumerPath"]
    assert "Query" in result
    assert "NamespaceName" in result


def test_wmi5861_defaults(host, user, ts, spec_stub):
    result = wmi.generate(5861, {}, host, user, spec_stub, ts)
    assert "ConsumerName" in result
    assert "Query" in result


def test_unknown_wmi_eid_raises(host, user, ts, spec_stub):
    with pytest.raises(ValueError, match="not implemented"):
        wmi.generate(9999, {}, host, user, spec_stub, ts)
