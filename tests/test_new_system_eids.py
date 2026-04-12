"""Tests for v0.7 new System EID generators."""

import pytest
from datetime import datetime, timezone
from artiforge.core.models import Host, User
from artiforge.generators import system


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


def test_7031_service_crash(host, user, ts, spec_stub):
    result = system.generate(7031, {"param1": "EvilSvc"}, host, user, spec_stub, ts)
    assert result["param1"] == "EvilSvc"
    assert "param2" in result
    assert "param3" in result
    assert "param4" in result

def test_7031_defaults(host, user, ts, spec_stub):
    result = system.generate(7031, {}, host, user, spec_stub, ts)
    assert result["param1"] == "WindowsUpdateSvc"

def test_7034_service_terminated(host, user, ts, spec_stub):
    result = system.generate(7034, {"param1": "EvilSvc", "param2": "3"}, host, user, spec_stub, ts)
    assert result["param1"] == "EvilSvc"
    assert result["param2"] == "3"

def test_7034_defaults(host, user, ts, spec_stub):
    result = system.generate(7034, {}, host, user, spec_stub, ts)
    assert result["param1"] == "WindowsUpdateSvc"
    assert result["param2"] == "1"
