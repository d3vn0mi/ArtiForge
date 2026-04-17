"""Forensic artifact orchestrator.

Scans a generated bundle for process execution events and produces
correlated Prefetch, Amcache, and $MFT artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from artiforge.core.models import ArtifactBundle


@dataclass
class ProcessInfo:
    image_path: str
    image_name: str
    parent_dir: str
    first_run: datetime
    run_count: int
    hashes: dict[str, str]
    file_version: str
    original_filename: str
    company: str
    host: str


def _parse_hashes(hash_str: str) -> dict[str, str]:
    result = {}
    if not hash_str:
        return result
    for part in hash_str.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def collect_process_info(bundle: ArtifactBundle) -> list[ProcessInfo]:
    seen: dict[tuple[str, str], ProcessInfo] = {}

    for ev in bundle.events:
        if ev.phase_id == 0:
            continue

        image = None
        if ev.channel == "Sysmon" and ev.eid == 1:
            image = ev.event_data.get("Image", "")
        elif ev.channel == "Security" and ev.eid == 4688:
            image = ev.event_data.get("NewProcessName", "")

        if not image:
            continue

        key = (ev.host, image)
        if key in seen:
            seen[key].run_count += 1
            if ev.timestamp < seen[key].first_run:
                seen[key].first_run = ev.timestamp
        else:
            name = image.rsplit("\\", 1)[-1] if "\\" in image else image
            parent = image.rsplit("\\", 1)[0] if "\\" in image else ""
            seen[key] = ProcessInfo(
                image_path=image, image_name=name, parent_dir=parent,
                first_run=ev.timestamp, run_count=1,
                hashes=_parse_hashes(ev.event_data.get("Hashes", "")),
                file_version=ev.event_data.get("FileVersion", ""),
                original_filename=ev.event_data.get("OriginalFileName", name),
                company=ev.event_data.get("Company", ""),
                host=ev.host,
            )

    return list(seen.values())


def generate(bundle: ArtifactBundle, output_dir: Path) -> list[Path]:
    from artiforge.generators.prefetch import generate_prefetch
    from artiforge.generators.amcache import generate_amcache
    from artiforge.generators.mft import generate_mft

    infos = collect_process_info(bundle)
    if not infos:
        return []

    by_host: dict[str, list[ProcessInfo]] = {}
    for info in infos:
        by_host.setdefault(info.host, []).append(info)

    written: list[Path] = []
    for host, host_infos in sorted(by_host.items()):
        host_dir = output_dir / host

        pf_dir = host_dir / "prefetch"
        pf_dir.mkdir(parents=True, exist_ok=True)
        for info in host_infos:
            written.append(generate_prefetch(info, pf_dir))

        written.append(generate_amcache(host_infos, host_dir))
        written.append(generate_mft(host_infos, host_dir))

    return written
