"""Noise temporal profiles and preset resolution."""

from __future__ import annotations

import random
from datetime import datetime, timedelta

_PRESETS = {
    "office_hours": {
        "logon_pairs": 5, "process_spawns": 10, "dns_queries": 8,
        "file_operations": 5, "registry_operations": 6, "service_changes": 2,
        "network_connections": 8, "windows_updates": 2,
    },
    "24x7_server": {
        "logon_pairs": 2, "process_spawns": 5, "dns_queries": 4,
        "file_operations": 2, "registry_operations": 3, "service_changes": 3,
        "network_connections": 6, "windows_updates": 2,
    },
    "developer_workstation": {
        "logon_pairs": 3, "process_spawns": 15, "dns_queries": 12,
        "file_operations": 8, "registry_operations": 10, "service_changes": 2,
        "network_connections": 10, "windows_updates": 1,
    },
}

_WEIGHT_CURVES = {
    "office_hours": [1,1,1,1,1,1,1,2,8,10,8,7,5,9,8,7,6,4,2,1,1,1,1,1],
    "24x7_server": [3,3,2,2,2,2,3,4,5,5,5,5,5,5,5,5,5,5,4,4,4,3,3,3],
    "developer_workstation": [1,1,1,1,1,1,1,3,9,10,8,6,3,8,9,8,7,5,3,2,2,3,2,1],
}

_ALL_FIELDS = [
    "logon_pairs", "process_spawns", "dns_queries",
    "file_operations", "registry_operations", "service_changes",
    "network_connections", "windows_updates",
]


def get_preset(name: str) -> dict[str, int] | None:
    return _PRESETS.get(name)


def resolve_counts(noise_profile: str | None, **explicit_counts: int) -> dict[str, int]:
    preset = _PRESETS.get(noise_profile) if noise_profile else None
    result = {}
    for field in _ALL_FIELDS:
        explicit = explicit_counts.get(field, 0)
        if explicit > 0:
            result[field] = explicit
        elif preset:
            result[field] = preset.get(field, 0)
        else:
            result[field] = 0
    return result


def sample_timestamp(base_time: datetime, spread_minutes: int, profile: str | None) -> datetime:
    spread_seconds = spread_minutes * 60
    if profile is None or profile not in _WEIGHT_CURVES:
        return base_time + timedelta(seconds=random.randint(0, spread_seconds))

    weights = _WEIGHT_CURVES[profile]
    bin_count = min(24, spread_minutes)
    bin_duration = spread_seconds / bin_count

    if bin_count < 24:
        step = 24 / bin_count
        bin_weights = []
        for i in range(bin_count):
            start_idx = int(i * step)
            end_idx = int((i + 1) * step)
            avg = sum(weights[start_idx:end_idx]) / (end_idx - start_idx)
            bin_weights.append(avg)
    else:
        bin_weights = list(weights)

    chosen_bin = random.choices(range(bin_count), weights=bin_weights, k=1)[0]
    bin_start = chosen_bin * bin_duration
    offset = bin_start + random.random() * bin_duration
    return base_time + timedelta(seconds=offset)
