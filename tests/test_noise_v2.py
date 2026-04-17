"""Tests for Noise Engine v2 — profiles, new generators, temporal distribution."""

import pytest
import random
from datetime import datetime, timedelta, timezone


def test_get_preset_office_hours():
    from artiforge.generators.noise_profiles import get_preset
    preset = get_preset("office_hours")
    assert preset["logon_pairs"] == 5
    assert preset["process_spawns"] == 10
    assert preset["file_operations"] == 5
    assert preset["windows_updates"] == 2


def test_get_preset_24x7_server():
    from artiforge.generators.noise_profiles import get_preset
    preset = get_preset("24x7_server")
    assert preset["logon_pairs"] == 2
    assert preset["service_changes"] == 3


def test_get_preset_developer_workstation():
    from artiforge.generators.noise_profiles import get_preset
    preset = get_preset("developer_workstation")
    assert preset["process_spawns"] == 15
    assert preset["dns_queries"] == 12


def test_get_preset_unknown_returns_none():
    from artiforge.generators.noise_profiles import get_preset
    assert get_preset("nonexistent") is None


def test_resolve_counts_no_profile():
    from artiforge.generators.noise_profiles import resolve_counts
    result = resolve_counts(
        noise_profile=None,
        logon_pairs=3, process_spawns=5, dns_queries=4,
        file_operations=0, registry_operations=0,
        service_changes=0, network_connections=0, windows_updates=0,
    )
    assert result["logon_pairs"] == 3
    assert result["file_operations"] == 0


def test_resolve_counts_with_profile_defaults():
    from artiforge.generators.noise_profiles import resolve_counts
    result = resolve_counts(
        noise_profile="office_hours",
        logon_pairs=0, process_spawns=0, dns_queries=0,
        file_operations=0, registry_operations=0,
        service_changes=0, network_connections=0, windows_updates=0,
    )
    assert result["logon_pairs"] == 5
    assert result["process_spawns"] == 10


def test_resolve_counts_with_profile_override():
    from artiforge.generators.noise_profiles import resolve_counts
    result = resolve_counts(
        noise_profile="office_hours",
        logon_pairs=20, process_spawns=0, dns_queries=0,
        file_operations=0, registry_operations=0,
        service_changes=0, network_connections=0, windows_updates=0,
    )
    assert result["logon_pairs"] == 20
    assert result["process_spawns"] == 10


def test_sample_timestamp_within_spread():
    from artiforge.generators.noise_profiles import sample_timestamp
    base = datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc)
    random.seed(42)
    for _ in range(100):
        ts = sample_timestamp(base, 60, "office_hours")
        delta = (ts - base).total_seconds()
        assert 0 <= delta <= 3600


def test_sample_timestamp_uniform_without_profile():
    from artiforge.generators.noise_profiles import sample_timestamp
    base = datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc)
    random.seed(42)
    ts = sample_timestamp(base, 60, None)
    delta = (ts - base).total_seconds()
    assert 0 <= delta <= 3600


def test_sample_timestamp_office_hours_biased():
    from artiforge.generators.noise_profiles import sample_timestamp
    base = datetime(2026, 2, 19, 0, 0, 0, tzinfo=timezone.utc)
    random.seed(42)
    timestamps = [sample_timestamp(base, 1440, "office_hours") for _ in range(1000)]
    morning = sum(1 for ts in timestamps if 480 <= (ts - base).total_seconds() / 60 < 720)
    night = sum(1 for ts in timestamps if (ts - base).total_seconds() / 60 < 360)
    assert morning > night * 2


from artiforge.core.models import Host, User


@pytest.fixture
def host():
    return Host(name="WIN-WS1", ip="10.10.10.10", fqdn="WIN-WS1.lab.local",
                sid_prefix="S-1-5-21-111-222-333",
                users=[User(username="marcus.webb", domain="LAB", rid=1001)])


@pytest.fixture
def user():
    return User(username="marcus.webb", domain="LAB", rid=1001)


@pytest.fixture
def ts():
    return datetime(2026, 2, 19, 9, 12, 0, tzinfo=timezone.utc)


def test_file_operation_produces_sysmon11(host, user, ts):
    from artiforge.generators.noise import file_operation
    ev = file_operation(host, user, ts, 1000)
    assert ev.channel == "Sysmon"
    assert ev.eid == 11
    assert ev.phase_id == 0
    assert "TargetFilename" in ev.event_data
    assert "Image" in ev.event_data


def test_registry_operation_produces_sysmon13(host, user, ts):
    from artiforge.generators.noise import registry_operation
    ev = registry_operation(host, user, ts, 1000)
    assert ev.channel == "Sysmon"
    assert ev.eid == 13
    assert ev.phase_id == 0
    assert "TargetObject" in ev.event_data
    assert "EventType" in ev.event_data


def test_service_change_produces_system7036(host, user, ts):
    from artiforge.generators.noise import service_change
    ev = service_change(host, user, ts, 1000)
    assert ev.channel == "System"
    assert ev.eid == 7036
    assert ev.phase_id == 0
    assert "param1" in ev.event_data
    assert "param2" in ev.event_data


def test_network_connection_produces_sysmon3(host, user, ts):
    from artiforge.generators.noise import network_connection
    ev = network_connection(host, user, ts, 1000)
    assert ev.channel == "Sysmon"
    assert ev.eid == 3
    assert ev.phase_id == 0
    assert "DestinationIp" in ev.event_data
    assert "DestinationPort" in ev.event_data
    assert "SourceIp" in ev.event_data


def test_windows_update_produces_three_events(host, user, ts):
    from artiforge.generators.noise import windows_update
    events = windows_update(host, user, ts, 1000)
    assert len(events) == 3
    eids = {ev.eid for ev in events}
    channels = {ev.channel for ev in events}
    assert 22 in eids   # DNS query
    assert 3 in eids    # network connection
    assert 11 in eids   # file create
    assert "Sysmon" in channels
    assert all(ev.phase_id == 0 for ev in events)


def test_windows_update_timestamps_close_together(host, user, ts):
    from artiforge.generators.noise import windows_update
    events = windows_update(host, user, ts, 1000)
    timestamps = sorted(ev.timestamp for ev in events)
    spread = (timestamps[-1] - timestamps[0]).total_seconds()
    assert spread <= 5
