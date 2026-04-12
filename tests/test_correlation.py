"""Tests for the event correlation context."""

import pytest
from artiforge.core.correlation import CorrelationContext, SessionState, ProcessState
from artiforge.core.models import Host


@pytest.fixture
def host():
    return Host(
        name="WIN-WS1",
        ip="10.10.10.10",
        fqdn="WIN-WS1.lab.local",
        sid_prefix="S-1-5-21-111-222-333",
    )


@pytest.fixture
def ctx(host):
    return CorrelationContext(host)


def test_register_session_returns_state(ctx):
    state = ctx.register_session("0x3a7f1c", "{GUID-1}", "marcus.webb")
    assert isinstance(state, SessionState)
    assert state.logon_id == "0x3a7f1c"
    assert state.logon_guid == "{GUID-1}"
    assert state.user == "marcus.webb"


def test_current_session_is_last_registered(ctx):
    ctx.register_session("0x100", "{G1}", "user1")
    ctx.register_session("0x200", "{G2}", "user2")
    assert ctx.current_session.logon_id == "0x200"


def test_get_session_by_label(ctx):
    ctx.register_session("0x100", "{G1}", "user1", label="admin")
    ctx.register_session("0x200", "{G2}", "user2", label="svc")
    assert ctx.get_session("admin").logon_id == "0x100"
    assert ctx.get_session("svc").logon_id == "0x200"


def test_get_session_default_label(ctx):
    ctx.register_session("0x100", "{G1}", "user1")
    assert ctx.get_session("default").logon_id == "0x100"


def test_get_session_nonexistent_returns_none(ctx):
    assert ctx.get_session("nonexistent") is None


def test_current_session_none_when_empty(ctx):
    assert ctx.current_session is None


# ── Process registration ─────────────────────────────────────────────────

def test_register_process_returns_state(ctx):
    state = ctx.register_process("{PG-1}", "5200", r"C:\Windows\System32\cmd.exe")
    assert isinstance(state, ProcessState)
    assert state.process_guid == "{PG-1}"
    assert state.process_id == "5200"
    assert state.image == r"C:\Windows\System32\cmd.exe"


def test_first_process_has_no_parent(ctx):
    state = ctx.register_process("{PG-1}", "5200", r"C:\Windows\System32\cmd.exe")
    assert state.parent_guid is None
    assert state.parent_id is None
    assert state.parent_image is None


def test_second_process_inherits_parent(ctx):
    ctx.register_process("{PG-1}", "5200", r"C:\Windows\System32\cmd.exe")
    child = ctx.register_process("{PG-2}", "7800", r"C:\Temp\mimikatz.exe")
    assert child.parent_guid == "{PG-1}"
    assert child.parent_id == "5200"
    assert child.parent_image == r"C:\Windows\System32\cmd.exe"


def test_current_process_is_last_registered(ctx):
    ctx.register_process("{PG-1}", "5200", r"C:\Windows\System32\cmd.exe")
    ctx.register_process("{PG-2}", "7800", r"C:\Temp\mimikatz.exe")
    assert ctx.current_process.process_guid == "{PG-2}"


def test_get_process_by_label(ctx):
    ctx.register_process("{PG-1}", "5200", r"C:\Windows\System32\cmd.exe", label="cmd")
    ctx.register_process("{PG-2}", "7800", r"C:\Temp\mimikatz.exe", label="mimi")
    assert ctx.get_process("cmd").process_id == "5200"
    assert ctx.get_process("mimi").process_id == "7800"


def test_get_process_nonexistent_returns_none(ctx):
    assert ctx.get_process("nonexistent") is None


def test_current_process_none_when_empty(ctx):
    assert ctx.current_process is None


def test_labeled_process_parent_comes_from_current(ctx):
    """When using labels, parent is always the current process at registration time."""
    ctx.register_process("{PG-1}", "5200", r"C:\Windows\System32\cmd.exe", label="cmd")
    ctx.register_process("{PG-2}", "7800", r"C:\Temp\mimi.exe", label="mimi")
    third = ctx.register_process("{PG-3}", "9000", r"C:\Temp\tool.exe", label="tool")
    assert third.parent_guid == "{PG-2}"


# ── Security generator integration tests ────────────────────────────────────

from artiforge.generators import security
from datetime import datetime, timezone


@pytest.fixture
def ts():
    return datetime(2026, 2, 19, 9, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def user():
    from artiforge.core.models import User
    return User(username="marcus.webb", domain="LAB", rid=1001)


@pytest.fixture
def spec_stub():
    class _Attack:
        malicious_account = "svc_backup_admin"
    class _Spec:
        attack = _Attack()
    return _Spec()


def test_4624_registers_session_in_context(ctx, user, ts, spec_stub):
    result = security.generate(
        4624, {}, ctx.host, user, spec_stub, ts,
        ctx=ctx, session_label="default", process_label="default",
    )
    session = ctx.get_session("default")
    assert session is not None
    assert session.logon_id == result["TargetLogonId"]
    assert session.logon_guid == result["LogonGuid"]


def test_4688_reads_logon_id_from_context(ctx, user, ts, spec_stub):
    security.generate(
        4624, {}, ctx.host, user, spec_stub, ts,
        ctx=ctx, session_label="default", process_label="default",
    )
    session = ctx.get_session("default")
    result = security.generate(
        4688, {}, ctx.host, user, spec_stub, ts,
        ctx=ctx, session_label="default", process_label="default",
    )
    assert result["SubjectLogonId"] == session.logon_id


def test_4634_reads_logon_id_from_context(ctx, user, ts, spec_stub):
    security.generate(
        4624, {}, ctx.host, user, spec_stub, ts,
        ctx=ctx, session_label="default", process_label="default",
    )
    session = ctx.get_session("default")
    result = security.generate(
        4634, {}, ctx.host, user, spec_stub, ts,
        ctx=ctx, session_label="default", process_label="default",
    )
    assert result["TargetLogonId"] == session.logon_id


def test_yaml_fields_override_correlation(ctx, user, ts, spec_stub):
    security.generate(
        4624, {}, ctx.host, user, spec_stub, ts,
        ctx=ctx, session_label="default", process_label="default",
    )
    result = security.generate(
        4688, {"SubjectLogonId": "0xOVERRIDE"}, ctx.host, user, spec_stub, ts,
        ctx=ctx, session_label="default", process_label="default",
    )
    assert result["SubjectLogonId"] == "0xOVERRIDE"


def test_no_context_falls_back_to_random(user, ts, spec_stub, host):
    result = security.generate(
        4688, {}, host, user, spec_stub, ts,
        ctx=None, session_label="default", process_label="default",
    )
    assert "SubjectLogonId" in result
