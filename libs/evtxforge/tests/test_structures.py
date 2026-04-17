"""Tests for EVTX binary structures — CRC32 and FILETIME."""

import pytest
from datetime import datetime, timezone


def test_crc32_known_value():
    from evtxforge.crc32 import compute_crc32
    import zlib
    data = b"ElfFile\x00"
    expected = zlib.crc32(data) & 0xFFFFFFFF
    assert compute_crc32(data) == expected


def test_crc32_empty():
    from evtxforge.crc32 import compute_crc32
    assert compute_crc32(b"") == 0


def test_crc32_returns_unsigned_32bit():
    from evtxforge.crc32 import compute_crc32
    result = compute_crc32(b"\xff" * 1000)
    assert 0 <= result <= 0xFFFFFFFF


def test_filetime_known_date():
    from evtxforge.crc32 import datetime_to_filetime
    dt = datetime(2026, 2, 19, 9, 12, 0, tzinfo=timezone.utc)
    ft = datetime_to_filetime(dt)
    expected = 1771492320 * 10_000_000 + 116444736000000000
    assert ft == expected


def test_filetime_epoch():
    from evtxforge.crc32 import datetime_to_filetime
    from evtxforge.constants import FILETIME_EPOCH_DIFF
    dt = datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert datetime_to_filetime(dt) == FILETIME_EPOCH_DIFF


import struct


# ── File header ──────────────────────────────────────────────────────────

def test_file_header_size():
    from evtxforge.structures import pack_file_header
    header = pack_file_header(num_chunks=1, next_record_id=1001, last_chunk_number=0)
    assert len(header) == 4096


def test_file_header_magic():
    from evtxforge.structures import pack_file_header
    header = pack_file_header(num_chunks=1, next_record_id=1, last_chunk_number=0)
    assert header[:8] == b"ElfFile\x00"


def test_file_header_version():
    from evtxforge.structures import pack_file_header
    header = pack_file_header(num_chunks=1, next_record_id=1, last_chunk_number=0)
    minor, major = struct.unpack_from("<HH", header, 36)
    assert major == 3
    assert minor == 1


def test_file_header_chunk_count():
    from evtxforge.structures import pack_file_header
    header = pack_file_header(num_chunks=5, next_record_id=1, last_chunk_number=4)
    count = struct.unpack_from("<H", header, 42)[0]
    assert count == 5


def test_file_header_crc_at_offset_124():
    from evtxforge.structures import pack_file_header
    from evtxforge.crc32 import compute_crc32
    header = pack_file_header(num_chunks=1, next_record_id=1, last_chunk_number=0)
    stored_crc = struct.unpack_from("<I", header, 124)[0]
    computed_crc = compute_crc32(header[:120])
    assert stored_crc == computed_crc


# ── Event record ─────────────────────────────────────────────────────────

def test_event_record_magic():
    from evtxforge.structures import pack_event_record
    record = pack_event_record(record_id=1000, filetime=0, binxml=b"\x0f\x01\x01\x00\x00")
    assert record[:4] == b"\x2a\x2a\x00\x00"


def test_event_record_trailing_size():
    from evtxforge.structures import pack_event_record
    binxml = b"\x0f\x01\x01\x00\x00"
    record = pack_event_record(record_id=1000, filetime=0, binxml=binxml)
    total_size = struct.unpack_from("<I", record, 4)[0]
    trailing_size = struct.unpack_from("<I", record, len(record) - 4)[0]
    assert total_size == trailing_size
    assert total_size == len(record)


def test_event_record_id():
    from evtxforge.structures import pack_event_record
    record = pack_event_record(record_id=42, filetime=0, binxml=b"\x00")
    record_id = struct.unpack_from("<Q", record, 8)[0]
    assert record_id == 42


def test_event_record_filetime():
    from evtxforge.structures import pack_event_record
    ft = 132500000000000000
    record = pack_event_record(record_id=1, filetime=ft, binxml=b"\x00")
    stored_ft = struct.unpack_from("<Q", record, 16)[0]
    assert stored_ft == ft


# ── Chunk ────────────────────────────────────────────────────────────────

def test_chunk_magic():
    from evtxforge.structures import pack_chunk
    chunk = pack_chunk(
        event_records_data=b"\x00" * 100,
        first_record_num=0, last_record_num=0,
        first_record_id=1, last_record_id=1,
    )
    assert chunk[:8] == b"ElfChnk\x00"


def test_chunk_size():
    from evtxforge.structures import pack_chunk
    chunk = pack_chunk(
        event_records_data=b"\x00" * 100,
        first_record_num=0, last_record_num=0,
        first_record_id=1, last_record_id=1,
    )
    assert len(chunk) == 65536


def test_chunk_event_records_crc():
    from evtxforge.structures import pack_chunk
    from evtxforge.crc32 import compute_crc32
    event_data = b"\x2a\x2a\x00\x00" + b"\xff" * 96
    chunk = pack_chunk(
        event_records_data=event_data,
        first_record_num=0, last_record_num=0,
        first_record_id=1, last_record_id=1,
    )
    stored_crc = struct.unpack_from("<I", chunk, 52)[0]
    computed_crc = compute_crc32(event_data)
    assert stored_crc == computed_crc


def test_chunk_header_crc():
    from evtxforge.structures import pack_chunk
    from evtxforge.crc32 import compute_crc32
    chunk = pack_chunk(
        event_records_data=b"\x00" * 100,
        first_record_num=0, last_record_num=0,
        first_record_id=1, last_record_id=1,
    )
    stored_crc = struct.unpack_from("<I", chunk, 124)[0]
    computed_crc = compute_crc32(chunk[:120] + chunk[128:512])
    assert stored_crc == computed_crc
