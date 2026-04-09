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


# ── v0.3 — Seed / deterministic generation ───────────────────────────────────

def test_seed_produces_identical_output():
    """Same seed → identical event_data for every event."""
    spec = engine.load_lab("uc3")
    b1 = engine.run(spec, seed=42)
    b2 = engine.run(spec, seed=42)
    assert len(b1.events) == len(b2.events)
    for e1, e2 in zip(b1.events, b2.events):
        assert e1.event_data == e2.event_data, (
            f"event_data mismatch at record {e1.record_id}"
        )


def test_different_seeds_produce_different_pids():
    """Different seeds should produce different random PIDs."""
    spec = engine.load_lab("uc3")
    b1 = engine.run(spec, seed=1)
    b2 = engine.run(spec, seed=999)
    # Collect all ProcessId / NewProcessId values
    def pids(bundle):
        result = []
        for e in bundle.events:
            result.append(e.event_data.get("ProcessId", ""))
            result.append(e.event_data.get("NewProcessId", ""))
        return result
    assert pids(b1) != pids(b2)


# ── v0.3 — Global jitter ─────────────────────────────────────────────────────

def test_jitter_shifts_timestamps():
    """--jitter N should move timestamps away from their base values."""
    spec = engine.load_lab("uc3")
    base = engine.run(spec, seed=1, jitter_seconds=0)
    jittered = engine.run(spec, seed=1, jitter_seconds=60)
    # At least some timestamps must differ
    diffs = [
        abs((e1.timestamp - e2.timestamp).total_seconds())
        for e1, e2 in zip(base.events, jittered.events)
    ]
    assert any(d > 0 for d in diffs), "Jitter produced no timestamp changes"
    # No event should be shifted more than 60 seconds
    assert all(d <= 60 for d in diffs), f"Jitter exceeded ±60s: max={max(diffs)}"


def test_jitter_zero_keeps_timestamps():
    """jitter_seconds=0 should not change any timestamps."""
    spec = engine.load_lab("uc3")
    b1 = engine.run(spec, seed=7, jitter_seconds=0)
    b2 = engine.run(spec, seed=7, jitter_seconds=0)
    for e1, e2 in zip(b1.events, b2.events):
        assert e1.timestamp == e2.timestamp


# ── v0.3 — Per-event jitter_seconds in YAML ──────────────────────────────────

def test_event_spec_jitter_field():
    """EventSpec.jitter_seconds is parsed correctly from YAML data."""
    from artiforge.core.models import EventSpec
    ev = EventSpec(channel="Security", eid=4624, jitter_seconds=10)
    assert ev.jitter_seconds == 10


def test_event_spec_repeat_jitter_field():
    from artiforge.core.models import EventSpec
    ev = EventSpec(channel="Sysmon", eid=3, repeat=5, repeat_gap_seconds=60,
                   repeat_jitter_seconds=15)
    assert ev.repeat_jitter_seconds == 15


# ── v0.3 — Repeat jitter (beaconing) ─────────────────────────────────────────

def test_repeat_jitter_varies_beacon_gaps():
    """repeat_jitter_seconds should produce non-uniform gaps between repeats."""
    from artiforge.core.models import EventSpec, LabSpec
    import yaml
    spec = engine.load_lab("uc3")
    # Build a minimal spec with one phase, one event with repeat jitter
    raw = yaml.safe_load((
        engine._labs_root() / "uc3" / "lab.yaml"
    ).read_text())
    # Use the engine directly with a jitter-bearing EventSpec via patch
    ev = EventSpec(
        channel="Sysmon", eid=3, offset_seconds=0,
        repeat=5, repeat_gap_seconds=60, repeat_jitter_seconds=30,
        fields={"DestinationIp": "198.41.192.227"},
    )
    from artiforge.core.models import Phase, AttackSpec
    from datetime import datetime, timezone
    phase = Phase(id=99, name="test", offset_minutes=0,
                  host="WIN-WS1", events=[ev])
    # Borrow infrastructure from UC3
    spec.attack.phases = [phase]
    spec.attack.noise = []
    bundle = engine.run(spec, seed=42)
    assert len(bundle.events) == 5
    timestamps = sorted(e.timestamp for e in bundle.events)
    gaps = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(4)]
    # With jitter ±30 around 60s, gaps should be between 30 and 90
    assert all(30 <= g <= 90 for g in gaps), f"Unexpected gaps: {gaps}"


# ── v0.3 — NoiseSpec model ───────────────────────────────────────────────────

def test_noise_spec_model():
    from artiforge.core.models import NoiseSpec
    n = NoiseSpec(host="WIN-WS1", spread_minutes=60, logon_pairs=3, process_spawns=5)
    assert n.host == "WIN-WS1"
    assert n.logon_pairs == 3
    assert n.process_spawns == 5
    assert n.dns_queries == 0  # default


def test_attack_spec_accepts_noise_list():
    from artiforge.core.models import AttackSpec, NoiseSpec
    from datetime import datetime, timezone
    a = AttackSpec(
        base_time=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc),
        noise=[NoiseSpec(host="WIN-WS1", logon_pairs=2)],
    )
    assert len(a.noise) == 1


# ── v0.3 — Noise injection via engine ────────────────────────────────────────

def _spec_with_noise(logon_pairs=2, process_spawns=3, dns_queries=4):
    """Return UC3 spec patched with a noise config on WIN-WS1."""
    spec = engine.load_lab("uc3")
    from artiforge.core.models import NoiseSpec
    spec.attack.noise = [NoiseSpec(
        host="WIN-WS1",
        spread_minutes=60,
        logon_pairs=logon_pairs,
        process_spawns=process_spawns,
        dns_queries=dns_queries,
    )]
    return spec


def test_noise_events_added_to_bundle():
    spec = _spec_with_noise(logon_pairs=2, process_spawns=3, dns_queries=4)
    bundle = engine.run(spec, seed=42)
    noise_events = [e for e in bundle.events if e.phase_name == "noise"]
    # 2 pairs × 2 = 4 logon events + 3 process + 4 dns = 11
    assert len(noise_events) == 11


def test_noise_events_have_phase_id_zero():
    spec = _spec_with_noise(logon_pairs=1, process_spawns=0, dns_queries=0)
    bundle = engine.run(spec, seed=42)
    noise = [e for e in bundle.events if e.phase_name == "noise"]
    assert all(e.phase_id == 0 for e in noise)


def test_noise_attack_events_still_present():
    """Noise injection must not replace attack events."""
    spec = _spec_with_noise(logon_pairs=5, process_spawns=10, dns_queries=8)
    bundle = engine.run(spec, seed=42)
    attack_events = [e for e in bundle.events if e.phase_name != "noise"]
    assert len(attack_events) == 40  # UC3 always has 40 attack events


def test_noise_timestamps_within_spread():
    spec = _spec_with_noise(process_spawns=10, logon_pairs=0, dns_queries=0)
    bundle = engine.run(spec, seed=42)
    noise = [e for e in bundle.events if e.phase_name == "noise"]
    assert noise, "No noise events generated"
    spread_end = bundle.base_time.replace(tzinfo=None)
    for ev in noise:
        ts = ev.timestamp.replace(tzinfo=None)
        delta = (ts - bundle.base_time.replace(tzinfo=None)).total_seconds()
        assert 0 <= delta <= 60 * 60 + 60, f"Noise timestamp out of spread: {delta}s"


def test_noise_skipped_when_phase_filter_set():
    """Noise is not injected when a phase_filter is active."""
    spec = _spec_with_noise(logon_pairs=5, process_spawns=5, dns_queries=5)
    bundle = engine.run(spec, seed=42, phase_filter=[1])
    noise = [e for e in bundle.events if e.phase_name == "noise"]
    assert noise == [], "Noise should not be injected during phase-filtered runs"


def test_noise_logon_events_are_4624_and_4634():
    spec = _spec_with_noise(logon_pairs=3, process_spawns=0, dns_queries=0)
    bundle = engine.run(spec, seed=42)
    noise = [e for e in bundle.events if e.phase_name == "noise"]
    eids = {e.eid for e in noise}
    assert 4624 in eids
    assert 4634 in eids


def test_noise_process_spawns_are_sysmon1():
    spec = _spec_with_noise(logon_pairs=0, process_spawns=5, dns_queries=0)
    bundle = engine.run(spec, seed=42)
    noise = [e for e in bundle.events if e.phase_name == "noise"]
    assert all(e.eid == 1 and e.channel == "Sysmon" for e in noise)


def test_noise_dns_queries_are_sysmon22():
    spec = _spec_with_noise(logon_pairs=0, process_spawns=0, dns_queries=5)
    bundle = engine.run(spec, seed=42)
    noise = [e for e in bundle.events if e.phase_name == "noise"]
    assert all(e.eid == 22 and e.channel == "Sysmon" for e in noise)


def test_noise_seed_deterministic():
    """Same seed → same noise events."""
    spec = _spec_with_noise(logon_pairs=3, process_spawns=5, dns_queries=4)
    b1 = engine.run(spec, seed=99)
    b2 = engine.run(spec, seed=99)
    n1 = [e for e in b1.events if e.phase_name == "noise"]
    n2 = [e for e in b2.events if e.phase_name == "noise"]
    assert len(n1) == len(n2)
    for e1, e2 in zip(n1, n2):
        assert e1.timestamp == e2.timestamp
        assert e1.eid == e2.eid


# ── v0.4: Schema versioning ────────────────────────────────────────────────────

def test_schema_version_default_is_1():
    """LabMeta defaults lab_schema_version to '1'."""
    spec = engine.load_lab("uc3")
    assert spec.lab.lab_schema_version == "1"


def test_schema_version_mismatch_raises_warning():
    """Loading a lab with a non-current schema version emits a UserWarning."""
    import warnings
    spec = engine.load_lab("uc3")
    # Patch in a different version
    object.__setattr__(spec.lab, "lab_schema_version", "99")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        engine.run(spec, seed=0)
    version_warnings = [x for x in w if issubclass(x.category, UserWarning)
                        and "schema version" in str(x.message).lower()]
    assert len(version_warnings) >= 1


# ── v0.4: compare_bundles ─────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def diff_result():
    spec_a = engine.load_lab("uc3")
    spec_b = engine.load_lab("uc3n")
    ba = engine.run(spec_a, seed=0)
    bb = engine.run(spec_b, seed=0)
    return engine.compare_bundles(ba, bb)


def test_compare_bundles_has_expected_keys(diff_result):
    for key in ("totals_a", "totals_b", "phases_a", "phases_b",
                "eids_a", "eids_b", "hosts_a", "hosts_b", "lab_a", "lab_b"):
        assert key in diff_result


def test_compare_bundles_totals_a_has_no_noise():
    """UC3 has no noise — noise count should be 0."""
    spec = engine.load_lab("uc3")
    ba = engine.run(spec, seed=0)
    bb = engine.run(spec, seed=0)
    result = engine.compare_bundles(ba, bb)
    assert result["totals_a"]["noise"] == 0


def test_compare_bundles_totals_b_has_noise():
    """UC3N has noise — noise count for B should be > 0."""
    spec_a = engine.load_lab("uc3")
    spec_b = engine.load_lab("uc3n")
    ba = engine.run(spec_a, seed=0)
    bb = engine.run(spec_b, seed=0)
    result = engine.compare_bundles(ba, bb)
    assert result["totals_b"]["noise"] > 0


def test_compare_bundles_attack_counts_match(diff_result):
    """UC3 and UC3N have the same attack chain → same attack event count."""
    assert diff_result["totals_a"]["attack"] == diff_result["totals_b"]["attack"]


def test_compare_bundles_phases_present(diff_result):
    """Both labs have 5 attack phases."""
    assert len(diff_result["phases_a"]) == 5
    assert len(diff_result["phases_b"]) == 5


def test_compare_bundles_lab_names(diff_result):
    assert "Egg-Cellent Resume" in diff_result["lab_a"]
    assert "Egg-Cellent Resume" in diff_result["lab_b"]


def test_compare_bundles_eids_present(diff_result):
    """EID 3 (Sysmon network) must appear in both labs."""
    assert 3 in diff_result["eids_a"]
    assert 3 in diff_result["eids_b"]
