"""Tests for individual event generators — required fields, correct values."""

import pytest
from datetime import datetime, timezone
from artiforge.core.models import Host, User
from artiforge.generators import security, system, sysmon, application


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
