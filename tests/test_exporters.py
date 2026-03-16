"""Tests for XML and Elasticsearch NDJSON exporters."""

import json
import xml.etree.ElementTree as ET
import pytest
from pathlib import Path
from artiforge.core import engine
from artiforge.exporters import xml_exporter, elastic

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


@pytest.fixture
def bundle():
    return engine.run(engine.load_lab("uc3"))


@pytest.fixture
def xml_dir(bundle, tmp_path):
    xml_exporter.export(bundle, tmp_path / "events")
    return tmp_path / "events"


@pytest.fixture
def ndjson_path(bundle, tmp_path):
    return elastic.export(bundle, tmp_path / "elastic")


# ── XML exporter ──────────────────────────────────────────────────────────────

def test_xml_correct_file_count(xml_dir):
    files = list(xml_dir.glob("*.xml"))
    assert len(files) == 7


def test_xml_expected_filenames(xml_dir):
    names = {f.name for f in xml_dir.glob("*.xml")}
    assert "WIN-WS1_Security.xml" in names
    assert "WIN-WS1_Sysmon.xml" in names
    assert "WIN-WS1_System.xml" in names
    assert "WIN-WS1_Application.xml" in names
    assert "WIN-BACKUP1_Security.xml" in names
    assert "WIN-WS2_Security.xml" in names
    assert "WIN-WS2_Sysmon.xml" in names


def test_xml_files_are_well_formed(xml_dir):
    for xml_path in xml_dir.glob("*.xml"):
        try:
            ET.parse(xml_path)
        except ET.ParseError as ex:
            pytest.fail(f"{xml_path.name} is not well-formed XML: {ex}")


def test_xml_events_have_correct_namespace(xml_dir):
    tree = ET.parse(xml_dir / "WIN-WS1_Security.xml")
    events = tree.getroot().findall("e:Event", NS)
    assert len(events) > 0


def test_xml_security_event_data_populated(xml_dir):
    tree = ET.parse(xml_dir / "WIN-WS1_Security.xml")
    for ev in tree.getroot().findall("e:Event", NS):
        eid = ev.findtext("e:System/e:EventID", namespaces=NS)
        if eid == "4688":
            cmdline = next(
                (d.text for d in ev.findall("e:EventData/e:Data", NS)
                 if d.get("Name") == "CommandLine"),
                None,
            )
            assert cmdline is not None
            break
    else:
        pytest.fail("No EID 4688 found in WIN-WS1_Security.xml")


def test_xml_computer_name_correct(xml_dir):
    tree = ET.parse(xml_dir / "WIN-WS1_Security.xml")
    for ev in tree.getroot().findall("e:Event", NS):
        computer = ev.findtext("e:System/e:Computer", namespaces=NS)
        assert computer == "WIN-WS1.lab.local"


def test_xml_timestamps_in_system_time_format(xml_dir):
    tree = ET.parse(xml_dir / "WIN-WS1_Security.xml")
    for ev in tree.getroot().findall("e:Event", NS):
        tc = ev.find("e:System/e:TimeCreated", NS)
        ts = tc.get("SystemTime")
        assert "T" in ts and "Z" in ts


def test_xml_sysmon_channel_path(xml_dir):
    tree = ET.parse(xml_dir / "WIN-WS1_Sysmon.xml")
    for ev in tree.getroot().findall("e:Event", NS):
        chan = ev.findtext("e:System/e:Channel", namespaces=NS)
        assert chan == "Microsoft-Windows-Sysmon/Operational"
        break


def test_xml_record_ids_unique_per_file(xml_dir):
    for xml_path in xml_dir.glob("*.xml"):
        tree = ET.parse(xml_path)
        rids = [
            ev.findtext("e:System/e:EventRecordID", namespaces=NS)
            for ev in tree.getroot().findall("e:Event", NS)
        ]
        assert len(rids) == len(set(rids)), f"Duplicate record IDs in {xml_path.name}"


# ── Elastic exporter ──────────────────────────────────────────────────────────

def test_ndjson_file_exists(ndjson_path):
    assert ndjson_path.exists()


def test_ndjson_line_count(ndjson_path, bundle):
    lines = ndjson_path.read_text().strip().splitlines()
    assert len(lines) == len(bundle.events) * 2   # action + document per event


def test_ndjson_all_lines_valid_json(ndjson_path):
    for i, line in enumerate(ndjson_path.read_text().strip().splitlines()):
        try:
            json.loads(line)
        except json.JSONDecodeError as ex:
            pytest.fail(f"Invalid JSON at line {i + 1}: {ex}")


def test_ndjson_action_lines(ndjson_path):
    lines = ndjson_path.read_text().strip().splitlines()
    for i in range(0, len(lines), 2):
        action = json.loads(lines[i])
        assert "index" in action
        assert "_index" in action["index"]
        assert "winlogbeat-artiforge-uc3" in action["index"]["_index"]


def test_ndjson_document_ecs_fields(ndjson_path):
    lines = ndjson_path.read_text().strip().splitlines()
    doc = json.loads(lines[1])   # first document
    assert "@timestamp" in doc
    assert "winlog" in doc
    assert "host" in doc
    assert "event" in doc
    assert "artiforge" in doc


def test_ndjson_winlog_fields(ndjson_path):
    lines = ndjson_path.read_text().strip().splitlines()
    doc = json.loads(lines[1])
    wl = doc["winlog"]
    assert "event_id" in wl
    assert "channel" in wl
    assert "computer_name" in wl
    assert "event_data" in wl


def test_ndjson_all_phases_present(ndjson_path):
    lines = ndjson_path.read_text().strip().splitlines()
    phases = {
        json.loads(lines[i]).get("artiforge", {}).get("phase_id")
        for i in range(1, len(lines), 2)
    }
    assert phases == {1, 2, 3, 4, 5}


def test_ndjson_process_fields_promoted_for_4688(ndjson_path):
    lines = ndjson_path.read_text().strip().splitlines()
    for i in range(1, len(lines), 2):
        doc = json.loads(lines[i])
        if doc["winlog"]["event_id"] == 4688:
            assert "process" in doc
            assert "command_line" in doc["process"]
            break
    else:
        pytest.fail("No EID 4688 document found in NDJSON")


def test_ndjson_network_fields_promoted_for_sysmon3(ndjson_path):
    lines = ndjson_path.read_text().strip().splitlines()
    found = False
    for i in range(1, len(lines), 2):
        doc = json.loads(lines[i])
        if (doc["winlog"]["event_id"] == 3 and
                "Sysmon" in doc["winlog"]["channel"]):
            assert "destination" in doc
            assert "source" in doc
            assert "network" in doc
            found = True
            break
    assert found, "No Sysmon EID 3 document found in NDJSON"
