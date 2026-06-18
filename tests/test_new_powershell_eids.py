"""Tests for v0.7 new PowerShell EID generators."""

import pytest
from datetime import datetime, timezone
from artiforge.core.models import Host, User
from artiforge.generators import powershell


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


def test_4105_script_start(host, user, ts, spec_stub):
    result = powershell.generate(4105, {"CommandLine": "Invoke-Mimikatz"}, host, user, spec_stub, ts)
    assert result["CommandLine"] == "Invoke-Mimikatz"
    assert result["HostName"] == "ConsoleHost"
    assert "RunspaceId" in result
    assert "HostId" in result

def test_4105_defaults(host, user, ts, spec_stub):
    result = powershell.generate(4105, {}, host, user, spec_stub, ts)
    assert "SequenceNumber" in result
    assert "EngineVersion" in result

def test_4106_script_stop(host, user, ts, spec_stub):
    result = powershell.generate(4106, {}, host, user, spec_stub, ts)
    assert result["HostName"] == "ConsoleHost"
    assert "RunspaceId" in result

def test_40961_engine_start(host, user, ts, spec_stub):
    result = powershell.generate(40961, {}, host, user, spec_stub, ts)
    assert result["HostName"] == "ConsoleHost"
    assert "EngineVersion" in result
    assert "RunspaceId" in result
    assert "HostId" in result

def test_40962_engine_stop(host, user, ts, spec_stub):
    result = powershell.generate(40962, {}, host, user, spec_stub, ts)
    assert result["HostName"] == "ConsoleHost"
    assert "RunspaceId" in result
