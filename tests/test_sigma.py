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


import tempfile
import yaml


def _write_sigma(tmp_path, filename, content):
    p = tmp_path / filename
    p.write_text(yaml.dump(content, default_flow_style=False), encoding="utf-8")
    return p


def _valid_sigma():
    return {
        "title": "Test Rule",
        "id": "test-001",
        "logsource": {"product": "windows", "service": "sysmon", "category": "process_creation"},
        "detection": {
            "selection": {"Image|endswith": "\\cmd.exe"},
            "condition": "selection",
        },
        "level": "high",
        "description": "Detects cmd.exe",
        "tags": ["attack.execution", "attack.t1059"],
    }


def test_load_sigma_rule_valid(tmp_path):
    from artiforge.detectors.sigma_loader import load_sigma_rule
    p = _write_sigma(tmp_path, "test.yml", _valid_sigma())
    rule = load_sigma_rule(p)
    assert rule is not None
    assert rule.title == "Test Rule"
    assert rule.logsource.service == "sysmon"
    assert rule.source_path == p


def test_load_sigma_rule_missing_title(tmp_path):
    from artiforge.detectors.sigma_loader import load_sigma_rule
    data = _valid_sigma()
    del data["title"]
    p = _write_sigma(tmp_path, "bad.yml", data)
    rule = load_sigma_rule(p)
    assert rule is None


def test_load_sigma_rule_missing_detection(tmp_path):
    from artiforge.detectors.sigma_loader import load_sigma_rule
    data = _valid_sigma()
    del data["detection"]
    p = _write_sigma(tmp_path, "bad.yml", data)
    rule = load_sigma_rule(p)
    assert rule is None


def test_load_sigma_rule_unsupported_aggregation(tmp_path):
    from artiforge.detectors.sigma_loader import load_sigma_rule
    data = _valid_sigma()
    data["detection"]["condition"] = "selection | count() > 5"
    p = _write_sigma(tmp_path, "agg.yml", data)
    rule = load_sigma_rule(p)
    assert rule is None


def test_load_sigma_dir(tmp_path):
    from artiforge.detectors.sigma_loader import load_sigma_dir
    _write_sigma(tmp_path, "rule1.yml", _valid_sigma())
    data2 = _valid_sigma()
    data2["title"] = "Rule 2"
    _write_sigma(tmp_path, "rule2.yml", data2)
    rules = load_sigma_dir(tmp_path)
    assert len(rules) == 2


def test_load_sigma_dir_skips_non_yml(tmp_path):
    from artiforge.detectors.sigma_loader import load_sigma_dir
    _write_sigma(tmp_path, "rule.yml", _valid_sigma())
    (tmp_path / "readme.txt").write_text("not a rule")
    rules = load_sigma_dir(tmp_path)
    assert len(rules) == 1


def test_load_sigma_dir_empty(tmp_path):
    from artiforge.detectors.sigma_loader import load_sigma_dir
    rules = load_sigma_dir(tmp_path)
    assert rules == []
