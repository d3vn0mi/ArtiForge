"""Windows Prefetch (.pf) binary file generator.

Produces Prefetch version 30 (Windows 10+) files with correct headers.
"""

from __future__ import annotations

import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path

from artiforge.generators.forensic_artifacts import ProcessInfo

_FILETIME_EPOCH_DIFF = 116444736000000000


def _to_filetime(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    unix_seconds = int(dt.timestamp())
    microseconds = dt.microsecond
    ticks = unix_seconds * 10_000_000 + microseconds * 10
    return ticks + _FILETIME_EPOCH_DIFF


def prefetch_hash(path: str) -> int:
    return zlib.crc32(path.upper().encode("utf-16-le")) & 0xFFFFFFFF


def generate_prefetch(info: ProcessInfo, output_dir: Path) -> Path:
    pf_hash = prefetch_hash(info.image_path)
    filename = f"{info.image_name.upper()}-{pf_hash:08X}.pf"
    out_path = output_dir / filename

    buf = bytearray(184)
    struct.pack_into("<I", buf, 0, 30)          # Version
    buf[4:8] = b"MAM\x04"                       # Magic
    struct.pack_into("<I", buf, 8, 0x11)         # Unknown
    struct.pack_into("<I", buf, 12, 184)         # File size

    exe_upper = info.image_name.upper()
    name_encoded = exe_upper.encode("utf-16-le")[:120]
    name_encoded = name_encoded.ljust(120, b"\x00")
    buf[16:136] = name_encoded

    struct.pack_into("<I", buf, 136, pf_hash)
    struct.pack_into("<Q", buf, 144, _to_filetime(info.first_run))
    struct.pack_into("<I", buf, 176, info.run_count)

    out_path.write_bytes(bytes(buf))
    return out_path
