"""CRC32 checksum and FILETIME conversion utilities."""

from __future__ import annotations

import zlib
from datetime import datetime, timezone

from evtxforge.constants import FILETIME_EPOCH_DIFF


def compute_crc32(data: bytes) -> int:
    """Compute CRC-32 (RFC 1952) and return as unsigned 32-bit integer."""
    return zlib.crc32(data) & 0xFFFFFFFF


def datetime_to_filetime(dt: datetime) -> int:
    """Convert a datetime to Windows FILETIME (100ns ticks since 1601-01-01)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    unix_seconds = int(dt.timestamp())
    microseconds = dt.microsecond
    ticks = unix_seconds * 10_000_000 + microseconds * 10
    return ticks + FILETIME_EPOCH_DIFF
