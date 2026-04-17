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
