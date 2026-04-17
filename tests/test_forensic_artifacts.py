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
