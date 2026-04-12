"""Tests for the event correlation context."""

import pytest
from artiforge.core.correlation import CorrelationContext, SessionState
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
