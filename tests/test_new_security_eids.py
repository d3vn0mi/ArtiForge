"""Tests for v0.7 new Security EID generators."""

import pytest
from datetime import datetime, timezone
from artiforge.core.models import Host, User
from artiforge.generators import security


@pytest.fixture
def host():
    return Host(name="WIN-WS1", ip="10.10.10.10", fqdn="WIN-WS1.lab.local",
                sid_prefix="S-1-5-21-111-222-333")

@pytest.fixture
def user():
    return User(username="marcus.webb", domain="LAB", rid=1001)

@pytest.fixture
def ts():
    return datetime(2026, 2, 19, 9, 12, 0, tzinfo=timezone.utc)

@pytest.fixture
def spec_stub():
    class _Attack:
        malicious_account = "svc_backup_admin"
    class _Spec:
        attack = _Attack()
    return _Spec()


def test_1102_has_subject_fields(host, user, ts, spec_stub):
    result = security.generate(1102, {}, host, user, spec_stub, ts)
    assert result["SubjectUserName"] == "marcus.webb"
    assert result["SubjectDomainName"] == "LAB"
    assert "SubjectLogonId" in result
    assert "SubjectUserSid" in result


def test_4697_service_fields(host, user, ts, spec_stub):
    result = security.generate(4697, {
        "ServiceName": "EvilSvc",
        "ServiceFileName": r"C:\Temp\evil.exe",
    }, host, user, spec_stub, ts)
    assert result["ServiceName"] == "EvilSvc"
    assert result["ServiceFileName"] == r"C:\Temp\evil.exe"
    assert "ServiceType" in result
    assert "ServiceStartType" in result
    assert "ServiceAccount" in result

def test_4697_defaults(host, user, ts, spec_stub):
    result = security.generate(4697, {}, host, user, spec_stub, ts)
    assert result["ServiceName"] == "WindowsUpdateSvc"


def test_4703_token_fields(host, user, ts, spec_stub):
    result = security.generate(4703, {
        "EnabledPrivilegeList": "SeDebugPrivilege",
    }, host, user, spec_stub, ts)
    assert result["EnabledPrivilegeList"] == "SeDebugPrivilege"
    assert result["ObjectType"] == "Token"
    assert "ProcessName" in result
    assert "SubjectLogonId" in result
    assert "TargetLogonId" in result


def test_4719_audit_policy(host, user, ts, spec_stub):
    result = security.generate(4719, {}, host, user, spec_stub, ts)
    assert "CategoryId" in result
    assert "SubcategoryId" in result
    assert "AuditPolicyChanges" in result
    assert "SubjectUserName" in result


def test_4735_group_changed(host, user, ts, spec_stub):
    result = security.generate(4735, {
        "TargetUserName": "Remote Desktop Users",
    }, host, user, spec_stub, ts)
    assert result["TargetUserName"] == "Remote Desktop Users"
    assert "SubjectLogonId" in result
    assert "SamAccountName" in result

def test_4735_defaults(host, user, ts, spec_stub):
    result = security.generate(4735, {}, host, user, spec_stub, ts)
    assert result["TargetUserName"] == "Administrators"
    assert result["TargetSid"] == "S-1-5-32-544"
