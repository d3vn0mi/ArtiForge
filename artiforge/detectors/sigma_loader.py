"""Load and validate Sigma YAML rule files."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

from artiforge.detectors.sigma_models import LogSource, SigmaRule

_UNSUPPORTED_CONDITION = re.compile(
    r"\b(count|min|max|sum|avg|near)\s*\(", re.IGNORECASE
)
_UNSUPPORTED_MODIFIERS = {"|re", "|base64", "|base64offset", "|cidr"}


def load_sigma_rule(path: Path) -> SigmaRule | None:
    """Parse a single Sigma YAML file. Returns None if invalid/unsupported."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"  [sigma] skip {path.name}: YAML parse error: {exc}", file=sys.stderr)
        return None

    if not isinstance(raw, dict):
        return None

    title = raw.get("title")
    detection = raw.get("detection")
    logsource_raw = raw.get("logsource", {})

    if not title:
        print(f"  [sigma] skip {path.name}: missing 'title'", file=sys.stderr)
        return None
    if not detection or not isinstance(detection, dict):
        print(f"  [sigma] skip {path.name}: missing 'detection'", file=sys.stderr)
        return None

    condition = detection.get("condition", "")
    if not condition:
        print(f"  [sigma] skip {path.name}: missing 'detection.condition'", file=sys.stderr)
        return None

    if _UNSUPPORTED_CONDITION.search(str(condition)):
        print(f"  [sigma] skip {path.name}: aggregation condition not supported", file=sys.stderr)
        return None

    for key, block in detection.items():
        if key == "condition":
            continue
        if isinstance(block, dict):
            for field_name in block:
                for mod in _UNSUPPORTED_MODIFIERS:
                    if mod in field_name:
                        print(f"  [sigma] skip {path.name}: unsupported modifier '{mod}'", file=sys.stderr)
                        return None

    logsource = LogSource(
        product=logsource_raw.get("product"),
        service=logsource_raw.get("service"),
        category=logsource_raw.get("category"),
    )

    return SigmaRule(
        title=title, id=raw.get("id"),
        logsource=logsource, detection=detection,
        level=raw.get("level", "medium"),
        description=raw.get("description", ""),
        tags=raw.get("tags", []),
        source_path=path,
    )


def load_sigma_dir(dir_path: Path) -> list[SigmaRule]:
    """Load all .yml files from a directory. Skips invalid/unsupported rules."""
    if not dir_path.is_dir():
        return []
    rules = []
    for p in sorted(dir_path.glob("*.yml")):
        rule = load_sigma_rule(p)
        if rule is not None:
            rules.append(rule)
    return rules
