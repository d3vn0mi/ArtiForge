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
