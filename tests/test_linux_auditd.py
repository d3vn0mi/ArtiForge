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


from artiforge.core.models import ArtifactBundle, GeneratedEvent


def _make_auditd_event(eid, event_data, host="LNX-WEB1", record_id=1000, ts=None):
    if ts is None:
        ts = datetime(2026, 2, 19, 9, 12, 0, tzinfo=timezone.utc)
    return GeneratedEvent(
        record_id=record_id, timestamp=ts, channel="Auditd", eid=eid,
        host=host, computer="lnx-web1.lab.local",
        provider_name="auditd", provider_guid="",
        event_data=event_data, phase_id=1, phase_name="test",
    )


def test_auditd_exporter_creates_file(tmp_path):
    from artiforge.exporters.auditd_exporter import export
    bundle = ArtifactBundle(
        lab_id="test", lab_name="Test",
        base_time=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc),
        events=[
            _make_auditd_event(1300, {"arch": "c000003e", "syscall": "59",
                                       "exe": "/usr/bin/bash", "pid": "5678",
                                       "uid": "0", "success": "yes"}),
        ],
    )
    files = export(bundle, tmp_path)
    assert len(files) == 1
    assert files[0].name == "LNX-WEB1_audit.log"
    assert files[0].exists()


def test_auditd_exporter_format(tmp_path):
    from artiforge.exporters.auditd_exporter import export
    bundle = ArtifactBundle(
        lab_id="test", lab_name="Test",
        base_time=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc),
        events=[
            _make_auditd_event(1300, {"arch": "c000003e", "syscall": "59",
                                       "exe": "/usr/bin/bash", "pid": "5678",
                                       "uid": "0", "success": "yes"}),
        ],
    )
    export(bundle, tmp_path)
    content = (tmp_path / "LNX-WEB1_audit.log").read_text()
    assert "type=SYSCALL" in content
    assert "msg=audit(" in content
    assert "arch=c000003e" in content
    assert "exe=/usr/bin/bash" in content


def test_auditd_exporter_skips_windows_events(tmp_path):
    from artiforge.exporters.auditd_exporter import export
    bundle = ArtifactBundle(
        lab_id="test", lab_name="Test",
        base_time=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc),
        events=[
            GeneratedEvent(
                record_id=1, timestamp=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc),
                channel="Security", eid=4624, host="WIN-WS1",
                computer="WIN-WS1.lab.local",
                provider_name="Microsoft-Windows-Security-Auditing",
                provider_guid="{54849625}", event_data={"TargetUserName": "admin"},
                phase_id=1, phase_name="test",
            ),
        ],
    )
    files = export(bundle, tmp_path)
    assert len(files) == 0


def test_auditd_exporter_one_file_per_host(tmp_path):
    from artiforge.exporters.auditd_exporter import export
    bundle = ArtifactBundle(
        lab_id="test", lab_name="Test",
        base_time=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc),
        events=[
            _make_auditd_event(1300, {"exe": "/usr/bin/bash"}, host="LNX-WEB1"),
            _make_auditd_event(1100, {"msg": "test", "pid": "1", "uid": "0", "auid": "1000", "ses": "1"}, host="LNX-DB1", record_id=1001),
        ],
    )
    files = export(bundle, tmp_path)
    assert len(files) == 2
    names = {f.name for f in files}
    assert "LNX-WEB1_audit.log" in names
    assert "LNX-DB1_audit.log" in names


def test_ecs_auditd_event_module():
    from artiforge.exporters.elastic import _to_ecs
    ev = _make_auditd_event(1300, {"exe": "/usr/bin/bash", "pid": "5678",
                                    "uid": "0", "comm": '"bash"'})
    doc = _to_ecs(ev)
    assert doc["event"]["module"] == "auditd"


def test_ecs_auditd_process_fields():
    from artiforge.exporters.elastic import _to_ecs
    ev = _make_auditd_event(1300, {"exe": "/usr/bin/bash", "pid": "5678",
                                    "uid": "0", "comm": '"bash"'})
    doc = _to_ecs(ev)
    assert doc["process"]["executable"] == "/usr/bin/bash"
    assert doc["process"]["pid"] == 5678


def test_ecs_auditd_user_fields():
    from artiforge.exporters.elastic import _to_ecs
    ev = _make_auditd_event(1300, {"exe": "/usr/bin/bash", "uid": "1000",
                                    "auid": "1000"})
    doc = _to_ecs(ev)
    assert doc["user"]["id"] == "1000"


def test_cli_format_includes_auditd():
    from click.testing import CliRunner
    from artiforge.cli import main
    runner = CliRunner()
    result = runner.invoke(main, ["generate", "--help"])
    assert "auditd" in result.output
