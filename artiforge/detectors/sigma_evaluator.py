"""Lightweight Sigma rule evaluator."""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from artiforge.core.models import GeneratedEvent
from artiforge.detectors.sigma_models import LogSource, SigmaRule

_SERVICE_CHANNEL = {
    "sysmon": "Sysmon", "security": "Security", "system": "System",
    "powershell": "PowerShell", "application": "Application", "wmi": "WMI",
}

_CATEGORY_FILTER = {
    "process_creation": ("Sysmon", [1]),
    "network_connection": ("Sysmon", [3]),
    "file_event": ("Sysmon", [11]),
    "registry_event": ("Sysmon", [12, 13, 14]),
    "dns_query": ("Sysmon", [22]),
    "process_access": ("Sysmon", [10]),
    "image_load": ("Sysmon", [7]),
    "pipe_created": ("Sysmon", [17, 18]),
    "file_delete": ("Sysmon", [23, 26]),
    "driver_load": ("Sysmon", [6]),
    "create_remote_thread": ("Sysmon", [8]),
    "process_tampering": ("Sysmon", [25]),
    "clipboard_change": ("Sysmon", [24]),
}

_CATEGORY_SECURITY = {
    "process_creation": ("Security", [4688]),
}


def _filter_by_logsource(events: list[GeneratedEvent], logsource: LogSource) -> list[GeneratedEvent]:
    if logsource.category:
        cat = logsource.category.lower()
        if cat in _CATEGORY_FILTER:
            channel, eids = _CATEGORY_FILTER[cat]
            return [e for e in events if e.channel == channel and e.eid in eids]
        if cat in _CATEGORY_SECURITY:
            channel, eids = _CATEGORY_SECURITY[cat]
            return [e for e in events if e.channel == channel and e.eid in eids]
    if logsource.service:
        channel = _SERVICE_CHANNEL.get(logsource.service.lower())
        if channel:
            return [e for e in events if e.channel == channel]
    return list(events)


def _parse_field_spec(field_spec: str) -> tuple[str, list[str]]:
    parts = field_spec.split("|")
    return parts[0], parts[1:]


def _match_value(event_value: str, pattern: str, modifiers: list[str]) -> bool:
    ev_lower = event_value.lower()
    pat_lower = pattern.lower()
    if "contains" in modifiers:
        return pat_lower in ev_lower
    if "startswith" in modifiers:
        return ev_lower.startswith(pat_lower)
    if "endswith" in modifiers:
        return ev_lower.endswith(pat_lower)
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(ev_lower, pat_lower)
    return ev_lower == pat_lower


def _match_field(event_data: dict, field_spec: str, values: Any) -> bool:
    field_name, modifiers = _parse_field_spec(field_spec)
    event_value = str(event_data.get(field_name, ""))
    if not isinstance(values, list):
        values = [values]
    str_values = [str(v) for v in values]
    if "all" in modifiers:
        return all(_match_value(event_value, v, modifiers) for v in str_values)
    return any(_match_value(event_value, v, modifiers) for v in str_values)


def _match_selection(event: GeneratedEvent, selection: dict) -> bool:
    for field_spec, values in selection.items():
        if not _match_field(event.event_data, field_spec, values):
            return False
    return True


def _get_selections(detection: dict) -> dict[str, dict]:
    return {k: v for k, v in detection.items() if k != "condition" and isinstance(v, dict)}


def _eval_condition(condition: str, selections: dict[str, dict], event: GeneratedEvent) -> bool:
    condition = condition.strip()

    m = re.match(r"^1 of (\w+)\*$", condition)
    if m:
        prefix = m.group(1)
        return any(
            _match_selection(event, sel)
            for name, sel in selections.items()
            if name.startswith(prefix)
        )

    m = re.match(r"^all of (\w+)\*$", condition)
    if m:
        prefix = m.group(1)
        matching = [n for n in selections if n.startswith(prefix)]
        return bool(matching) and all(_match_selection(event, selections[n]) for n in matching)

    m = re.match(r"^(\w+)\s+and\s+not\s+(\w+)$", condition)
    if m:
        return (
            _match_selection(event, selections.get(m.group(1), {}))
            and not _match_selection(event, selections.get(m.group(2), {}))
        )

    if " or " in condition and " and " not in condition:
        return any(
            _match_selection(event, selections.get(p.strip(), {}))
            for p in condition.split(" or ")
        )

    if " and " in condition and " not " not in condition:
        return all(
            _match_selection(event, selections.get(p.strip(), {}))
            for p in condition.split(" and ")
        )

    m = re.match(r"^not\s+(\w+)$", condition)
    if m:
        return not _match_selection(event, selections.get(m.group(1), {}))

    return _match_selection(event, selections.get(condition, {}))


def evaluate_rule(rule: SigmaRule, events: list[GeneratedEvent]) -> list[GeneratedEvent]:
    """Evaluate a Sigma rule against a list of events.

    Returns only events that match the rule's logsource filter and detection
    condition. Noise events (phase_id == 0) are excluded from evaluation.
    """
    attack_events = [e for e in events if e.phase_id != 0]
    candidates = _filter_by_logsource(attack_events, rule.logsource)
    selections = _get_selections(rule.detection)
    condition = rule.detection.get("condition", "")
    return [e for e in candidates if _eval_condition(condition, selections, e)]
