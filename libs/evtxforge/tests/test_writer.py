"""Integration tests for EvtxWriter."""

import struct
import pytest
from datetime import datetime, timezone

from evtxforge import EvtxWriter
from evtxforge.constants import FILE_HEADER_SIZE, CHUNK_SIZE, FILE_MAGIC, CHUNK_MAGIC


@pytest.fixture
def tmp_evtx(tmp_path):
    return tmp_path / "test.evtx"


def test_writer_creates_file(tmp_evtx):
    with EvtxWriter(tmp_evtx) as w:
        w.write_event(
            channel="Security", event_id=4624,
            provider_name="Microsoft-Windows-Security-Auditing",
            provider_guid="{54849625-5478-4994-A5BA-3E3B0328C30D}",
            computer="WIN-WS1.lab.local",
            timestamp=datetime(2026, 2, 19, 9, 12, 0, tzinfo=timezone.utc),
            event_data={"TargetUserName": "marcus.webb"},
        )
    assert tmp_evtx.exists()


def test_writer_file_size_single_event(tmp_evtx):
    with EvtxWriter(tmp_evtx) as w:
        w.write_event(
            channel="Security", event_id=4624, provider_name="Test",
            provider_guid="{00000000-0000-0000-0000-000000000000}",
            computer="PC1",
            timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            event_data={},
        )
    assert tmp_evtx.stat().st_size == FILE_HEADER_SIZE + CHUNK_SIZE


def test_writer_file_header_magic(tmp_evtx):
    with EvtxWriter(tmp_evtx) as w:
        w.write_event(
            channel="Security", event_id=1, provider_name="Test",
            provider_guid="{00000000-0000-0000-0000-000000000000}",
            computer="PC1",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            event_data={},
        )
    data = tmp_evtx.read_bytes()
    assert data[:8] == FILE_MAGIC


def test_writer_chunk_magic(tmp_evtx):
    with EvtxWriter(tmp_evtx) as w:
        w.write_event(
            channel="Security", event_id=1, provider_name="Test",
            provider_guid="{00000000-0000-0000-0000-000000000000}",
            computer="PC1",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            event_data={},
        )
    data = tmp_evtx.read_bytes()
    assert data[FILE_HEADER_SIZE:FILE_HEADER_SIZE + 8] == CHUNK_MAGIC


def test_writer_auto_increment_record_id(tmp_evtx):
    with EvtxWriter(tmp_evtx) as w:
        w.write_event(
            channel="Security", event_id=1, provider_name="Test",
            provider_guid="{00000000-0000-0000-0000-000000000000}",
            computer="PC1",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            event_data={},
        )
        w.write_event(
            channel="Security", event_id=2, provider_name="Test",
            provider_guid="{00000000-0000-0000-0000-000000000000}",
            computer="PC1",
            timestamp=datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
            event_data={},
        )
    data = tmp_evtx.read_bytes()
    first_id = struct.unpack_from("<Q", data, FILE_HEADER_SIZE + 512 + 8)[0]
    assert first_id == 1
    first_size = struct.unpack_from("<I", data, FILE_HEADER_SIZE + 512 + 4)[0]
    second_id = struct.unpack_from("<Q", data, FILE_HEADER_SIZE + 512 + first_size + 8)[0]
    assert second_id == 2


def test_writer_explicit_record_id(tmp_evtx):
    with EvtxWriter(tmp_evtx) as w:
        w.write_event(
            channel="Security", event_id=1, provider_name="Test",
            provider_guid="{00000000-0000-0000-0000-000000000000}",
            computer="PC1",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            event_data={},
            record_id=1000,
        )
    data = tmp_evtx.read_bytes()
    record_id = struct.unpack_from("<Q", data, FILE_HEADER_SIZE + 512 + 8)[0]
    assert record_id == 1000


def test_writer_multiple_events(tmp_evtx):
    with EvtxWriter(tmp_evtx) as w:
        for i in range(10):
            w.write_event(
                channel="Security", event_id=4624, provider_name="Test",
                provider_guid="{00000000-0000-0000-0000-000000000000}",
                computer="PC1",
                timestamp=datetime(2026, 1, 1, 0, i, 0, tzinfo=timezone.utc),
                event_data={"User": f"user{i}"},
            )
    assert tmp_evtx.stat().st_size == FILE_HEADER_SIZE + CHUNK_SIZE


def test_writer_context_manager_finalizes_on_exception(tmp_evtx):
    try:
        with EvtxWriter(tmp_evtx) as w:
            w.write_event(
                channel="Security", event_id=1, provider_name="Test",
                provider_guid="{00000000-0000-0000-0000-000000000000}",
                computer="PC1",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                event_data={},
            )
            raise ValueError("test error")
    except ValueError:
        pass
    assert tmp_evtx.exists()
    assert tmp_evtx.stat().st_size == FILE_HEADER_SIZE + CHUNK_SIZE
