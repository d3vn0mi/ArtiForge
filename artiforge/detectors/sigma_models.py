"""Data models for Sigma rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LogSource:
    """Sigma logsource specification."""
    product: str | None = None
    service: str | None = None
    category: str | None = None


@dataclass
class SigmaRule:
    """A parsed Sigma detection rule."""
    title: str
    id: str | None
    logsource: LogSource
    detection: dict
    level: str
    description: str
    tags: list[str] = field(default_factory=list)
    source_path: Path | None = None

    @property
    def mitre_ids(self) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from tags."""
        pattern = re.compile(r"^attack\.t(\d+(?:\.\d+)*)$", re.IGNORECASE)
        result = []
        for tag in self.tags:
            m = pattern.match(tag)
            if m:
                result.append(f"T{m.group(1)}")
        return result
