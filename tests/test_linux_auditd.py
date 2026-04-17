"""Tests for Linux auditd channel — model, generators, exporters."""

import pytest
from datetime import datetime, timezone
from artiforge.core.models import Host, User


def test_host_platform_defaults_to_windows():
    h = Host(name="WIN-WS1", ip="10.10.10.10", fqdn="WIN-WS1.lab.local")
    assert h.platform == "windows"


def test_host_platform_linux():
    h = Host(name="LNX-WEB1", ip="10.10.10.50", fqdn="lnx-web1.lab.local",
             platform="linux", os="Ubuntu 22.04 LTS")
    assert h.platform == "linux"
    assert h.os == "Ubuntu 22.04 LTS"


def test_existing_host_backward_compat():
    h = Host(name="WIN-WS1", ip="10.10.10.10", fqdn="WIN-WS1.lab.local",
             os="Windows 10 22H2", sid_prefix="S-1-5-21-111-222-333")
    assert h.platform == "windows"
    assert h.user_sid(1001) == "S-1-5-21-111-222-333-1001"


def test_linux_host_with_users():
    h = Host(name="LNX-WEB1", ip="10.10.10.50", fqdn="lnx-web1.lab.local",
             platform="linux", os="Ubuntu 22.04 LTS",
             users=[User(username="www-data", domain="lnx-web1", rid=33)])
    assert h.users[0].username == "www-data"
    assert h.users[0].rid == 33


@pytest.fixture
def linux_host():
    return Host(name="LNX-WEB1", ip="10.10.10.50", fqdn="lnx-web1.lab.local",
                platform="linux", os="Ubuntu 22.04 LTS",
                users=[User(username="root", domain="lnx-web1", rid=0)])

@pytest.fixture
def linux_user():
    return User(username="root", domain="lnx-web1", rid=0)

@pytest.fixture
def ts():
    return datetime(2026, 2, 19, 9, 12, 0, tzinfo=timezone.utc)

@pytest.fixture
def spec_stub():
    class _Attack:
        malicious_account = "attacker"
    class _Spec:
        attack = _Attack()
    return _Spec()


def test_syscall_generator(linux_host, linux_user, ts, spec_stub):
    from artiforge.generators.linux_auditd import generate
    result = generate(eid=1300, fields={"syscall": "59", "exe": "/usr/bin/bash"},
                      host=linux_host, user=linux_user, spec=spec_stub, timestamp=ts)
    assert result["arch"] == "c000003e"
    assert result["syscall"] == "59"
    assert result["exe"] == "/usr/bin/bash"
    assert "pid" in result
    assert "uid" in result


def test_execve_generator(linux_host, linux_user, ts, spec_stub):
    from artiforge.generators.linux_auditd import generate
    result = generate(eid=1309, fields={"args": ["bash", "-c", "whoami"]},
                      host=linux_host, user=linux_user, spec=spec_stub, timestamp=ts)
    assert result["argc"] == "3"
    assert result["a0"] == "bash"
    assert result["a1"] == "-c"
    assert result["a2"] == "whoami"


def test_path_generator(linux_host, linux_user, ts, spec_stub):
    from artiforge.generators.linux_auditd import generate
    result = generate(eid=1302, fields={"name": "/usr/bin/bash"},
                      host=linux_host, user=linux_user, spec=spec_stub, timestamp=ts)
    assert result["name"] == "/usr/bin/bash"
    assert "inode" in result
    assert "mode" in result


def test_sockaddr_generator(linux_host, linux_user, ts, spec_stub):
    from artiforge.generators.linux_auditd import generate
    result = generate(eid=1306, fields={"addr": "10.10.10.10", "port": "443"},
                      host=linux_host, user=linux_user, spec=spec_stub, timestamp=ts)
    assert result["addr"] == "10.10.10.10"
    assert result["port"] == "443"
    assert result["family"] == "inet"


def test_user_auth_generator(linux_host, linux_user, ts, spec_stub):
    from artiforge.generators.linux_auditd import generate
    result = generate(eid=1100, fields={"acct": "root", "res": "success",
                                         "exe": "/usr/bin/sudo"},
                      host=linux_host, user=linux_user, spec=spec_stub, timestamp=ts)
    assert "root" in result["msg"]
    assert "success" in result["msg"]
    assert "pid" in result


def test_user_login_generator(linux_host, linux_user, ts, spec_stub):
    from artiforge.generators.linux_auditd import generate
    result = generate(eid=1101, fields={"exe": "/usr/sbin/sshd",
                                         "hostname": "10.10.10.10", "res": "success"},
                      host=linux_host, user=linux_user, spec=spec_stub, timestamp=ts)
    assert "sshd" in result["msg"]
    assert "success" in result["msg"]
    assert "pid" in result


def test_cred_acq_generator(linux_host, linux_user, ts, spec_stub):
    from artiforge.generators.linux_auditd import generate
    result = generate(eid=1103, fields={"acct": "root", "exe": "/usr/bin/sudo",
                                         "res": "success"},
                      host=linux_host, user=linux_user, spec=spec_stub, timestamp=ts)
    assert "sudo" in result["msg"]
    assert "pid" in result


def test_string_alias_syscall(linux_host, linux_user, ts, spec_stub):
    from artiforge.generators.linux_auditd import resolve_eid
    assert resolve_eid("SYSCALL") == 1300
    assert resolve_eid("EXECVE") == 1309
    assert resolve_eid("USER_AUTH") == 1100
    assert resolve_eid(1300) == 1300


def test_unknown_eid_raises(linux_host, linux_user, ts, spec_stub):
    from artiforge.generators.linux_auditd import generate
    with pytest.raises(ValueError, match="not implemented"):
        generate(eid=9999, fields={}, host=linux_host, user=linux_user,
                 spec=spec_stub, timestamp=ts)


def test_dispatch_auditd_channel(linux_host, linux_user, ts, spec_stub):
    from artiforge.generators import dispatch_event
    result = dispatch_event(
        channel="Auditd", eid=1300,
        fields={"exe": "/usr/bin/bash"},
        host=linux_host, user=linux_user, spec=spec_stub, timestamp=ts,
    )
    assert result["exe"] == "/usr/bin/bash"
    assert result["arch"] == "c000003e"


def test_dispatch_unknown_channel_raises(linux_host, linux_user, ts, spec_stub):
    from artiforge.generators import dispatch_event
    with pytest.raises(ValueError, match="Unknown channel"):
        dispatch_event(
            channel="FakeChannel", eid=1,
            fields={}, host=linux_host, user=linux_user,
            spec=spec_stub, timestamp=ts,
        )
