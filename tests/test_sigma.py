"""Tests for the Sigma rule evaluator."""

import pytest
from pathlib import Path


def test_logsource_defaults():
    from artiforge.detectors.sigma_models import LogSource
    ls = LogSource()
    assert ls.product is None
    assert ls.service is None
    assert ls.category is None


def test_logsource_with_values():
    from artiforge.detectors.sigma_models import LogSource
    ls = LogSource(product="windows", service="sysmon", category="process_creation")
    assert ls.product == "windows"
    assert ls.service == "sysmon"
    assert ls.category == "process_creation"


def test_sigma_rule_fields():
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(
        title="Test Rule", id="test-001",
        logsource=LogSource(product="windows", service="security"),
        detection={"selection": {"EventID": "4624"}, "condition": "selection"},
        level="high", description="A test rule",
        tags=["attack.t1078"], source_path=None,
    )
    assert rule.title == "Test Rule"
    assert rule.logsource.service == "security"
    assert rule.level == "high"
    assert "attack.t1078" in rule.tags


def test_sigma_rule_mitre_ids():
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(
        title="Test", id=None, logsource=LogSource(),
        detection={}, level="medium", description="",
        tags=["attack.execution", "attack.t1059.001", "attack.t1218"],
        source_path=None,
    )
    assert rule.mitre_ids == ["T1059.001", "T1218"]
