"""Tests for the engine — phase runner, timestamp resolution, artifact counts."""

import pytest
from datetime import datetime, timezone
from collections import Counter
from artiforge.core import engine
from artiforge.core.models import ArtifactBundle


@pytest.fixture
def uc3_bundle():
    spec = engine.load_lab("uc3")
    return engine.run(spec)


# ── Bundle basics ─────────────────────────────────────────────────────────────

def test_bundle_returns_artifact_bundle(uc3_bundle):
    assert isinstance(uc3_bundle, ArtifactBundle)


def test_total_event_count(uc3_bundle):
    assert len(uc3_bundle.events) == 40


def test_total_file_count(uc3_bundle):
    assert len(uc3_bundle.files) == 5


def test_lab_id_in_bundle(uc3_bundle):
    assert uc3_bundle.lab_id == "uc3"


# ── Phase coverage ────────────────────────────────────────────────────────────

def test_all_phases_represented(uc3_bundle):
    phase_ids = {e.phase_id for e in uc3_bundle.events}
    assert phase_ids == {1, 2, 3, 4, 5}


def test_phase_event_counts(uc3_bundle):
    counts = Counter(e.phase_id for e in uc3_bundle.events)
    assert counts[1] == 9   # +1 initial 4624 logon
    assert counts[2] == 5
    assert counts[3] == 6
    assert counts[4] == 12  # 5 individual Sysmon 3 events (exponential backoff)
    assert counts[5] == 8   # +1 Sysmon 3 RDP, +1 4672 special privileges


# ── Host distribution ─────────────────────────────────────────────────────────

def test_events_on_correct_hosts(uc3_bundle):
    hosts = {e.host for e in uc3_bundle.events}
    assert "WIN-WS1" in hosts
    assert "WIN-BACKUP1" in hosts
    assert "WIN-WS2" in hosts


def test_account_creation_events_on_backup1(uc3_bundle):
    backup_events = [e for e in uc3_bundle.events if e.host == "WIN-BACKUP1"]
    eids = {e.eid for e in backup_events}
    assert 4720 in eids   # account created
    assert 4732 in eids   # added to Administrators
    assert 4648 in eids   # explicit creds


def test_rdp_logon_on_ws2(uc3_bundle):
    ws2_events = [e for e in uc3_bundle.events if e.host == "WIN-WS2"]
    eids = {e.eid for e in ws2_events}
    assert 4624 in eids
    assert 4634 in eids


# ── Timestamps ────────────────────────────────────────────────────────────────

def test_timestamps_are_utc_aware(uc3_bundle):
    for ev in uc3_bundle.events:
        assert ev.timestamp.tzinfo is not None


def test_timestamps_monotonically_increase_per_host(uc3_bundle):
    """Events on each host should appear in chronological order."""
    from collections import defaultdict
    by_host = defaultdict(list)
    for ev in uc3_bundle.events:
        by_host[ev.host].append(ev.timestamp)
    for host, ts_list in by_host.items():
        assert ts_list == sorted(ts_list), f"Out-of-order timestamps on {host}"


def test_phase_offsets_respected(uc3_bundle):
    """Phase 2 events (T+15m) must all be after Phase 1 events (T+0)."""
    p1_max = max(e.timestamp for e in uc3_bundle.events if e.phase_id == 1)
    p2_min = min(e.timestamp for e in uc3_bundle.events if e.phase_id == 2)
    assert p2_min > p1_max


def test_base_time_override(uc3_bundle):
    spec = engine.load_lab("uc3")
    custom_time = datetime(2026, 3, 15, 8, 0, 0, tzinfo=timezone.utc)
    bundle = engine.run(spec, base_time_override=custom_time)
    earliest = min(e.timestamp for e in bundle.events)
    assert earliest.year == 2026
    assert earliest.month == 3
    assert earliest.day == 15


# ── Key events ────────────────────────────────────────────────────────────────

def test_lolbas_chain_events_present(uc3_bundle):
    """ie4uinit → msxsl → cmd chain must appear in Security/Sysmon logs."""
    cmdlines = [
        e.event_data.get("CommandLine", "") or e.event_data.get("CommandLine", "")
        for e in uc3_bundle.events
    ]
    assert any("ie4uinit.exe -BaseSettings" in c for c in cmdlines)
    assert any("msxsl.exe" in c for c in cmdlines)
    assert any("whoami" in c for c in cmdlines)


def test_schtasks_xml_cmdline(uc3_bundle):
    cmdlines = [e.event_data.get("CommandLine", "") for e in uc3_bundle.events]
    assert any(
        "MicrosoftEdgeUpdateTaskMachineUA" in c and "/XML" in c
        for c in cmdlines if c
    )


def test_cloudflared_service_name(uc3_bundle):
    service_events = [e for e in uc3_bundle.events if e.eid == 7045]
    assert len(service_events) == 1
    assert service_events[0].event_data["ServiceName"] == "Wuauserv_Svc"
    assert "FAKE_TOKEN" in service_events[0].event_data["ImagePath"]


def test_sysmon3_repeated_5_times(uc3_bundle):
    """Cloudflared makes 5 failed outbound connection attempts."""
    sysmon3_phase4 = [
        e for e in uc3_bundle.events
        if e.eid == 3 and e.phase_id == 4 and e.channel == "Sysmon"
    ]
    assert len(sysmon3_phase4) == 5


def test_sysmon3_destination_is_argotunnel(uc3_bundle):
    sysmon3 = [e for e in uc3_bundle.events if e.eid == 3 and e.phase_id == 4]
    for ev in sysmon3:
        assert ev.event_data["DestinationHostname"] == "region2.v2.argotunnel.com"
        assert ev.event_data["DestinationPort"] == "443"


def test_rdp_logon_type_10(uc3_bundle):
    rdp_events = [e for e in uc3_bundle.events if e.eid == 4624 and e.host == "WIN-WS2"]
    assert len(rdp_events) == 1
    assert rdp_events[0].event_data["LogonType"] == "10"
    assert rdp_events[0].event_data["IpAddress"] == "10.10.10.10"


# ── Selective phase filter ────────────────────────────────────────────────────

def test_phase_filter_reduces_events(uc3_bundle):
    spec = engine.load_lab("uc3")
    bundle = engine.run(spec, phase_filter=[1])
    assert len(bundle.events) == 9
    assert all(e.phase_id == 1 for e in bundle.events)


def test_phase_filter_multiple(uc3_bundle):
    spec = engine.load_lab("uc3")
    bundle = engine.run(spec, phase_filter=[1, 4])
    phase_ids = {e.phase_id for e in bundle.events}
    assert phase_ids == {1, 4}
    assert len(bundle.events) == 9 + 12


# ── Record IDs ────────────────────────────────────────────────────────────────

def test_record_ids_are_unique(uc3_bundle):
    ids = [e.record_id for e in uc3_bundle.events]
    assert len(ids) == len(set(ids))


def test_record_ids_start_at_1000(uc3_bundle):
    assert min(e.record_id for e in uc3_bundle.events) == 1000


# ── Realism fixes ─────────────────────────────────────────────────────────────

def test_initial_logon_phase1(uc3_bundle):
    """Phase 1 must open with a 4624 logon establishing the marcus.webb session."""
    p1 = [e for e in uc3_bundle.events if e.phase_id == 1]
    eids = {e.eid for e in p1}
    assert 4624 in eids


def test_special_privileges_after_rdp(uc3_bundle):
    """4672 must immediately follow the 4624 RDP logon on WIN-WS2."""
    ws2 = sorted(
        [e for e in uc3_bundle.events if e.host == "WIN-WS2"],
        key=lambda e: e.timestamp,
    )
    eids = [e.eid for e in ws2]
    i = eids.index(4624)
    assert eids[i + 1] == 4672


def test_rdp_sysmon3_present(uc3_bundle):
    """Phase 5 must contain a Sysmon 3 event for the mstsc.exe → port 3389 connection."""
    rdp_net = [
        e for e in uc3_bundle.events
        if e.eid == 3 and e.phase_id == 5 and e.channel == "Sysmon"
    ]
    assert len(rdp_net) == 1
    assert rdp_net[0].event_data["DestinationPort"] == "3389"
