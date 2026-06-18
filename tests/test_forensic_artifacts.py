"""Tests for forensic artifact generation — Prefetch, Amcache, $MFT."""

import pytest
import json
from datetime import datetime, timezone
from pathlib import Path
from artiforge.core.models import ArtifactBundle, GeneratedEvent


def _make_sysmon1(image, host="WIN-WS1", record_id=1000, ts=None,
                   hashes="MD5=AABB,SHA256=CCDD", file_version="10.0",
                   original_filename=None, company="Microsoft"):
    if ts is None:
        ts = datetime(2026, 2, 19, 9, 15, 0, tzinfo=timezone.utc)
    name = image.rsplit("\\", 1)[-1] if "\\" in image else image
    return GeneratedEvent(
        record_id=record_id, timestamp=ts, channel="Sysmon", eid=1,
        host=host, computer=f"{host}.lab.local",
        provider_name="Microsoft-Windows-Sysmon",
        provider_guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
        event_data={
            "Image": image, "Hashes": hashes, "FileVersion": file_version,
            "OriginalFileName": original_filename or name, "Company": company,
        },
        phase_id=1, phase_name="test",
    )


def test_collect_process_info_from_sysmon1():
    from artiforge.generators.forensic_artifacts import collect_process_info
    events = [
        _make_sysmon1(r"C:\Temp\mimikatz.exe"),
        _make_sysmon1(r"C:\Windows\System32\cmd.exe"),
    ]
    bundle = ArtifactBundle(lab_id="test", lab_name="Test",
        base_time=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc), events=events)
    infos = collect_process_info(bundle)
    assert len(infos) == 2
    paths = {p.image_path for p in infos}
    assert r"C:\Temp\mimikatz.exe" in paths


def test_collect_deduplicates_by_host_and_path():
    from artiforge.generators.forensic_artifacts import collect_process_info
    events = [
        _make_sysmon1(r"C:\Temp\mimikatz.exe", record_id=1000),
        _make_sysmon1(r"C:\Temp\mimikatz.exe", record_id=1001,
                       ts=datetime(2026, 2, 19, 9, 20, 0, tzinfo=timezone.utc)),
    ]
    bundle = ArtifactBundle(lab_id="test", lab_name="Test",
        base_time=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc), events=events)
    infos = collect_process_info(bundle)
    assert len(infos) == 1
    assert infos[0].run_count == 2
    assert infos[0].first_run == datetime(2026, 2, 19, 9, 15, 0, tzinfo=timezone.utc)


def test_collect_skips_noise_events():
    from artiforge.generators.forensic_artifacts import collect_process_info
    noise = GeneratedEvent(
        record_id=1, timestamp=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc),
        channel="Sysmon", eid=1, host="WIN-WS1", computer="WIN-WS1.lab.local",
        provider_name="Microsoft-Windows-Sysmon", provider_guid="{5770385F}",
        event_data={"Image": r"C:\Windows\System32\chrome.exe", "Hashes": ""},
        phase_id=0, phase_name="noise")
    bundle = ArtifactBundle(lab_id="test", lab_name="Test",
        base_time=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc), events=[noise])
    assert len(collect_process_info(bundle)) == 0


def test_collect_separates_hosts():
    from artiforge.generators.forensic_artifacts import collect_process_info
    events = [
        _make_sysmon1(r"C:\Temp\mimikatz.exe", host="WIN-WS1"),
        _make_sysmon1(r"C:\Temp\mimikatz.exe", host="WIN-WS2", record_id=1001),
    ]
    bundle = ArtifactBundle(lab_id="test", lab_name="Test",
        base_time=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc), events=events)
    infos = collect_process_info(bundle)
    assert len(infos) == 2
    assert {p.host for p in infos} == {"WIN-WS1", "WIN-WS2"}


def test_process_info_fields():
    from artiforge.generators.forensic_artifacts import collect_process_info, ProcessInfo
    events = [
        _make_sysmon1(r"C:\Temp\mimikatz.exe", hashes="MD5=AABB,SHA256=CCDD",
                       file_version="2.2.0", original_filename="mimikatz.exe",
                       company="gentilkiwi"),
    ]
    bundle = ArtifactBundle(lab_id="test", lab_name="Test",
        base_time=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc), events=events)
    info = collect_process_info(bundle)[0]
    assert isinstance(info, ProcessInfo)
    assert info.image_name == "mimikatz.exe"
    assert info.parent_dir == r"C:\Temp"
    assert info.file_version == "2.2.0"
    assert info.original_filename == "mimikatz.exe"
    assert info.company == "gentilkiwi"
    assert "SHA256" in info.hashes


import struct


def test_prefetch_creates_pf_file(tmp_path):
    from artiforge.generators.prefetch import generate_prefetch
    from artiforge.generators.forensic_artifacts import ProcessInfo
    info = ProcessInfo(
        image_path=r"C:\Temp\mimikatz.exe", image_name="mimikatz.exe",
        parent_dir=r"C:\Temp",
        first_run=datetime(2026, 2, 19, 9, 15, 0, tzinfo=timezone.utc),
        run_count=1, hashes={"SHA256": "AABB"}, file_version="2.2.0",
        original_filename="mimikatz.exe", company="gentilkiwi", host="WIN-WS1")
    path = generate_prefetch(info, tmp_path)
    assert path.exists()
    assert path.suffix == ".pf"
    assert "MIMIKATZ.EXE" in path.name


def test_prefetch_filename_format(tmp_path):
    from artiforge.generators.prefetch import generate_prefetch, prefetch_hash
    from artiforge.generators.forensic_artifacts import ProcessInfo
    info = ProcessInfo(
        image_path=r"C:\Temp\mimikatz.exe", image_name="mimikatz.exe",
        parent_dir=r"C:\Temp",
        first_run=datetime(2026, 2, 19, 9, 15, 0, tzinfo=timezone.utc),
        run_count=1, hashes={}, file_version="", original_filename="",
        company="", host="WIN-WS1")
    path = generate_prefetch(info, tmp_path)
    pf_hash = prefetch_hash(r"C:\Temp\mimikatz.exe")
    assert path.name == f"MIMIKATZ.EXE-{pf_hash:08X}.pf"


def test_prefetch_binary_header(tmp_path):
    from artiforge.generators.prefetch import generate_prefetch
    from artiforge.generators.forensic_artifacts import ProcessInfo
    info = ProcessInfo(
        image_path=r"C:\Temp\mimikatz.exe", image_name="mimikatz.exe",
        parent_dir=r"C:\Temp",
        first_run=datetime(2026, 2, 19, 9, 15, 0, tzinfo=timezone.utc),
        run_count=3, hashes={}, file_version="", original_filename="",
        company="", host="WIN-WS1")
    path = generate_prefetch(info, tmp_path)
    data = path.read_bytes()
    version = struct.unpack_from("<I", data, 0)[0]
    assert version == 30
    assert data[4:8] == b"MAM\x04"
    run_count = struct.unpack_from("<I", data, 176)[0]
    assert run_count == 3


def test_prefetch_exe_name_in_header(tmp_path):
    from artiforge.generators.prefetch import generate_prefetch
    from artiforge.generators.forensic_artifacts import ProcessInfo
    info = ProcessInfo(
        image_path=r"C:\Temp\mimikatz.exe", image_name="mimikatz.exe",
        parent_dir=r"C:\Temp",
        first_run=datetime(2026, 2, 19, 9, 15, 0, tzinfo=timezone.utc),
        run_count=1, hashes={}, file_version="", original_filename="",
        company="", host="WIN-WS1")
    path = generate_prefetch(info, tmp_path)
    data = path.read_bytes()
    name_bytes = data[16:16 + 60 * 2]
    name = name_bytes.decode("utf-16-le").rstrip("\x00")
    assert name == "MIMIKATZ.EXE"


def test_prefetch_hash_deterministic():
    from artiforge.generators.prefetch import prefetch_hash
    h1 = prefetch_hash(r"C:\Temp\mimikatz.exe")
    h2 = prefetch_hash(r"C:\Temp\mimikatz.exe")
    assert h1 == h2
    h3 = prefetch_hash(r"C:\Windows\System32\cmd.exe")
    assert h1 != h3


def test_amcache_creates_json(tmp_path):
    from artiforge.generators.amcache import generate_amcache
    from artiforge.generators.forensic_artifacts import ProcessInfo
    infos = [ProcessInfo(
        image_path=r"C:\Temp\mimikatz.exe", image_name="mimikatz.exe",
        parent_dir=r"C:\Temp",
        first_run=datetime(2026, 2, 19, 9, 15, 0, tzinfo=timezone.utc),
        run_count=1, hashes={"SHA256": "AABB", "MD5": "CCDD"},
        file_version="2.2.0", original_filename="mimikatz.exe",
        company="gentilkiwi", host="WIN-WS1")]
    path = generate_amcache(infos, tmp_path)
    assert path.exists()
    assert path.name == "amcache_entries.json"


def test_amcache_json_structure(tmp_path):
    from artiforge.generators.amcache import generate_amcache
    from artiforge.generators.forensic_artifacts import ProcessInfo
    infos = [ProcessInfo(
        image_path=r"C:\Temp\mimikatz.exe", image_name="mimikatz.exe",
        parent_dir=r"C:\Temp",
        first_run=datetime(2026, 2, 19, 9, 15, 0, tzinfo=timezone.utc),
        run_count=1, hashes={"SHA256": "AABB"},
        file_version="2.2.0", original_filename="mimikatz.exe",
        company="gentilkiwi", host="WIN-WS1")]
    path = generate_amcache(infos, tmp_path)
    entries = json.loads(path.read_text())
    assert isinstance(entries, list)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["full_path"] == r"C:\Temp\mimikatz.exe"
    assert entry["sha1"] != ""
    assert entry["first_run"] == "2026-02-19T09:15:00Z"
    assert entry["file_version"] == "2.2.0"
    assert entry["publisher"] == "gentilkiwi"
    assert entry["original_filename"] == "mimikatz.exe"


def test_amcache_uses_sha1_from_hashes(tmp_path):
    from artiforge.generators.amcache import generate_amcache
    from artiforge.generators.forensic_artifacts import ProcessInfo
    infos = [ProcessInfo(
        image_path=r"C:\Temp\test.exe", image_name="test.exe",
        parent_dir=r"C:\Temp",
        first_run=datetime(2026, 1, 1, tzinfo=timezone.utc),
        run_count=1, hashes={"SHA1": "DA39A3EE5E6B"},
        file_version="", original_filename="", company="", host="WIN-WS1")]
    path = generate_amcache(infos, tmp_path)
    entries = json.loads(path.read_text())
    assert entries[0]["sha1"] == "DA39A3EE5E6B"


def test_mft_creates_json(tmp_path):
    from artiforge.generators.mft import generate_mft
    from artiforge.generators.forensic_artifacts import ProcessInfo
    infos = [ProcessInfo(
        image_path=r"C:\Temp\mimikatz.exe", image_name="mimikatz.exe",
        parent_dir=r"C:\Temp",
        first_run=datetime(2026, 2, 19, 9, 15, 0, tzinfo=timezone.utc),
        run_count=1, hashes={}, file_version="", original_filename="",
        company="", host="WIN-WS1")]
    path = generate_mft(infos, tmp_path)
    assert path.exists()
    assert path.name == "mft_entries.json"


def test_mft_json_structure(tmp_path):
    from artiforge.generators.mft import generate_mft
    from artiforge.generators.forensic_artifacts import ProcessInfo
    infos = [ProcessInfo(
        image_path=r"C:\Temp\mimikatz.exe", image_name="mimikatz.exe",
        parent_dir=r"C:\Temp",
        first_run=datetime(2026, 2, 19, 9, 15, 0, tzinfo=timezone.utc),
        run_count=1, hashes={}, file_version="", original_filename="",
        company="", host="WIN-WS1")]
    path = generate_mft(infos, tmp_path)
    entries = json.loads(path.read_text())
    assert isinstance(entries, list)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["filename"] == "mimikatz.exe"
    assert entry["parent_directory"] == r"C:\Temp"
    assert "created" in entry
    assert "modified" in entry
    assert "accessed" in entry
    assert "entry_modified" in entry
    assert entry["is_directory"] is False
    assert entry["in_use"] is True
    assert "record_number" in entry


def test_mft_record_numbers_unique(tmp_path):
    from artiforge.generators.mft import generate_mft
    from artiforge.generators.forensic_artifacts import ProcessInfo
    infos = [
        ProcessInfo(image_path=r"C:\Temp\a.exe", image_name="a.exe",
                     parent_dir=r"C:\Temp",
                     first_run=datetime(2026, 1, 1, tzinfo=timezone.utc),
                     run_count=1, hashes={}, file_version="",
                     original_filename="", company="", host="WIN-WS1"),
        ProcessInfo(image_path=r"C:\Temp\b.exe", image_name="b.exe",
                     parent_dir=r"C:\Temp",
                     first_run=datetime(2026, 1, 1, tzinfo=timezone.utc),
                     run_count=1, hashes={}, file_version="",
                     original_filename="", company="", host="WIN-WS1"),
    ]
    path = generate_mft(infos, tmp_path)
    entries = json.loads(path.read_text())
    record_nums = [e["record_number"] for e in entries]
    assert len(record_nums) == len(set(record_nums))


def test_mft_accessed_matches_first_run(tmp_path):
    from artiforge.generators.mft import generate_mft
    from artiforge.generators.forensic_artifacts import ProcessInfo
    first_run = datetime(2026, 2, 19, 9, 15, 5, tzinfo=timezone.utc)
    infos = [ProcessInfo(
        image_path=r"C:\Temp\tool.exe", image_name="tool.exe",
        parent_dir=r"C:\Temp", first_run=first_run,
        run_count=1, hashes={}, file_version="",
        original_filename="", company="", host="WIN-WS1")]
    path = generate_mft(infos, tmp_path)
    entries = json.loads(path.read_text())
    assert entries[0]["accessed"] == "2026-02-19T09:15:05Z"


def test_attack_spec_forensic_artifacts_default_false():
    from artiforge.core.models import AttackSpec
    a = AttackSpec(base_time=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert a.forensic_artifacts is False


def test_attack_spec_forensic_artifacts_true():
    from artiforge.core.models import AttackSpec
    a = AttackSpec(base_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                   forensic_artifacts=True)
    assert a.forensic_artifacts is True


def test_generate_full_produces_correlated_artifacts(tmp_path):
    """Prefetch, Amcache, $MFT should reference the same executables."""
    from artiforge.generators.forensic_artifacts import generate
    events = [
        _make_sysmon1(r"C:\Temp\mimikatz.exe", host="WIN-WS1"),
        _make_sysmon1(r"C:\Windows\System32\cmd.exe", host="WIN-WS1", record_id=1001),
    ]
    bundle = ArtifactBundle(
        lab_id="test", lab_name="Test",
        base_time=datetime(2026, 2, 19, 9, 0, 0, tzinfo=timezone.utc),
        events=events)
    files = generate(bundle, tmp_path)

    assert len(files) == 4  # 2 prefetch + 1 amcache + 1 mft

    pf_files = [f for f in files if f.suffix == ".pf"]
    assert len(pf_files) == 2

    amcache_files = [f for f in files if f.name == "amcache_entries.json"]
    assert len(amcache_files) == 1
    amcache = json.loads(amcache_files[0].read_text())
    amcache_paths = {e["full_path"] for e in amcache}
    assert r"C:\Temp\mimikatz.exe" in amcache_paths
    assert r"C:\Windows\System32\cmd.exe" in amcache_paths

    mft_files = [f for f in files if f.name == "mft_entries.json"]
    assert len(mft_files) == 1
    mft = json.loads(mft_files[0].read_text())
    mft_names = {e["filename"] for e in mft}
    assert "mimikatz.exe" in mft_names
    assert "cmd.exe" in mft_names


def test_uc3_no_forensic_artifacts_by_default():
    from artiforge.core import engine
    spec = engine.load_lab("uc3")
    assert spec.attack.forensic_artifacts is False
