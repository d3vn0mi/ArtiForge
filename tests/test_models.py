"""Tests for Pydantic models — ensure lab YAML parses correctly."""

import pytest
from datetime import timezone
from pydantic import ValidationError
from artiforge.core.models import Host, User, LabSpec, EventSpec, FileArtifactSpec
from artiforge.core import engine


@pytest.fixture
def uc3_spec():
    return engine.load_lab("uc3")


# ── Lab loading ───────────────────────────────────────────────────────────────

def test_load_lab_returns_labspec(uc3_spec):
    assert uc3_spec.lab.id == "uc3"
    assert uc3_spec.lab.name == "Egg-Cellent Resume"


def test_infrastructure_has_all_hosts(uc3_spec):
    hosts = uc3_spec.infrastructure.hosts
    assert "WIN-WS1" in hosts
    assert "WIN-WS2" in hosts
    assert "WIN-DC1" in hosts
    assert "WIN-BACKUP1" in hosts


def test_host_ips_correct(uc3_spec):
    hosts = uc3_spec.infrastructure.hosts
    assert hosts["WIN-WS1"].ip == "10.10.10.10"
    assert hosts["WIN-WS2"].ip == "10.10.10.11"
    assert hosts["WIN-DC1"].ip == "10.10.10.2"
    assert hosts["WIN-BACKUP1"].ip == "10.10.10.20"


def test_host_fqdns(uc3_spec):
    h = uc3_spec.infrastructure.hosts["WIN-WS1"]
    assert h.fqdn == "WIN-WS1.lab.local"


def test_ws1_has_user_marcus(uc3_spec):
    ws1 = uc3_spec.infrastructure.hosts["WIN-WS1"]
    user = ws1.get_user("marcus.webb")
    assert user is not None
    assert user.domain == "LAB"
    assert user.rid == 1001


def test_host_sid_method(uc3_spec):
    ws1 = uc3_spec.infrastructure.hosts["WIN-WS1"]
    sid = ws1.user_sid(1001)
    assert sid.startswith("S-1-5-21-")
    assert sid.endswith("-1001")


def test_five_phases(uc3_spec):
    assert len(uc3_spec.attack.phases) == 5


def test_phase_offsets(uc3_spec):
    offsets = [p.offset_minutes for p in uc3_spec.attack.phases]
    assert offsets == [0, 15, 60, 90, 120]


def test_base_time_is_utc(uc3_spec):
    bt = uc3_spec.attack.base_time
    assert bt.tzinfo is not None


def test_unknown_lab_raises():
    with pytest.raises(FileNotFoundError):
        engine.load_lab("nonexistent_lab_xyz")


def test_list_labs_includes_uc3():
    labs = engine.list_labs()
    ids = [l["id"] for l in labs]
    assert "uc3" in ids


def test_list_labs_event_count():
    labs = engine.list_labs()
    uc3 = next(l for l in labs if l["id"] == "uc3")
    assert uc3["events"] == 40
    assert uc3["phases"] == 5


# ── Pydantic validation constraints ───────────────────────────────────────────

def test_negative_offset_seconds_raises():
    with pytest.raises(ValidationError):
        EventSpec(channel="Security", eid=4688, offset_seconds=-1)


def test_zero_repeat_raises():
    with pytest.raises(ValidationError):
        EventSpec(channel="Security", eid=4688, repeat=0)


def test_invalid_artifact_type_raises():
    with pytest.raises(ValidationError):
        FileArtifactSpec(type="xml", dest=r"C:\foo\bar.xml")  # "xml" not in Literal
