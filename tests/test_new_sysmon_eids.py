"""Tests for v0.7 new Sysmon EID generators."""

import pytest
from datetime import datetime, timezone
from artiforge.core.models import Host, User
from artiforge.generators import sysmon


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


def test_sysmon6_driver_loaded(host, user, ts, spec_stub):
    result = sysmon.generate(6, {
        "ImageLoaded": r"C:\Windows\System32\drivers\evil.sys",
        "Signed": "false",
    }, host, user, spec_stub, ts)
    assert result["ImageLoaded"] == r"C:\Windows\System32\drivers\evil.sys"
    assert result["Signed"] == "false"
    assert "Hashes" in result
    assert "SignatureStatus" in result

def test_sysmon6_defaults(host, user, ts, spec_stub):
    result = sysmon.generate(6, {}, host, user, spec_stub, ts)
    assert "ImageLoaded" in result
    assert result["Signed"] == "false"

def test_sysmon15_ads(host, user, ts, spec_stub):
    result = sysmon.generate(15, {
        "TargetFilename": r"C:\Temp\file.txt:hidden",
    }, host, user, spec_stub, ts)
    assert result["TargetFilename"] == r"C:\Temp\file.txt:hidden"
    assert "ProcessGuid" in result
    assert "Hash" in result
    assert "Contents" in result

def test_sysmon16_config_change(host, user, ts, spec_stub):
    result = sysmon.generate(16, {}, host, user, spec_stub, ts)
    assert "Configuration" in result
    assert "ConfigurationFileHash" in result
    assert "UtcTime" in result

def test_sysmon24_clipboard(host, user, ts, spec_stub):
    result = sysmon.generate(24, {}, host, user, spec_stub, ts)
    assert "ProcessGuid" in result
    assert "Session" in result
    assert "Hashes" in result
    assert "User" in result

def test_sysmon26_file_delete(host, user, ts, spec_stub):
    result = sysmon.generate(26, {
        "TargetFilename": r"C:\Temp\payload.exe",
    }, host, user, spec_stub, ts)
    assert result["TargetFilename"] == r"C:\Temp\payload.exe"
    assert "ProcessGuid" in result
    assert "Hashes" in result
    assert "IsExecutable" in result
