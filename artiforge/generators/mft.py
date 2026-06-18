"""$MFT JSON artifact generator."""

from __future__ import annotations

import json
import zlib
from datetime import timedelta
from pathlib import Path

from artiforge.generators.forensic_artifacts import ProcessInfo


def _record_number(path: str) -> int:
    return (zlib.crc32(path.encode("utf-8")) & 0x7FFFFFFF) % 10000000 + 100000


def generate_mft(infos: list[ProcessInfo], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for info in infos:
        created = info.first_run - timedelta(seconds=5)
        accessed = info.first_run
        entries.append({
            "record_number": _record_number(info.image_path),
            "filename": info.image_name,
            "parent_directory": info.parent_dir,
            "file_size": 0,
            "created": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "modified": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "accessed": accessed.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "entry_modified": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "is_directory": False,
            "in_use": True,
        })
    out_path = output_dir / "mft_entries.json"
    out_path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return out_path
