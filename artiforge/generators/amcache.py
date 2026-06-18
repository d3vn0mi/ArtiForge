"""Amcache JSON artifact generator."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

from artiforge.generators.forensic_artifacts import ProcessInfo


def _generate_sha1(path: str) -> str:
    return hashlib.sha1(path.encode("utf-8")).hexdigest().upper()


def generate_amcache(infos: list[ProcessInfo], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for info in infos:
        sha1 = info.hashes.get("SHA1", _generate_sha1(info.image_path))
        entries.append({
            "full_path": info.image_path,
            "sha1": sha1,
            "file_size": 0,
            "first_run": info.first_run.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_modified": info.first_run.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "publisher": info.company,
            "file_version": info.file_version,
            "pe_header_checksum": "0x00000000",
            "original_filename": info.original_filename,
        })
    out_path = output_dir / "amcache_entries.json"
    out_path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return out_path
