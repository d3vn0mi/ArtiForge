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


# ── Evaluator tests ────────────────────────────────────────────────────────────

from datetime import datetime, timezone
from artiforge.core.models import GeneratedEvent


def _make_event(channel, eid, event_data, phase_id=1):
    return GeneratedEvent(
        record_id=1,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        channel=channel, eid=eid, host="WIN-WS1",
        computer="WIN-WS1.lab.local", provider_name="Test",
        provider_guid="{00000000-0000-0000-0000-000000000000}",
        event_data=event_data, phase_id=phase_id, phase_name="test",
    )


def test_evaluator_filters_by_channel():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="security"),
        detection={"selection": {"TargetUserName": "admin"}, "condition": "selection"},
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Security", 4624, {"TargetUserName": "admin"}),
        _make_event("Sysmon", 1, {"Image": "cmd.exe"}),
    ]
    matches = evaluate_rule(rule, events)
    assert len(matches) == 1
    assert matches[0].channel == "Security"


def test_evaluator_filters_by_category_eid():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", category="process_creation"),
        detection={"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\cmd.exe"}),
        _make_event("Sysmon", 3, {"Image": r"C:\Windows\System32\cmd.exe"}),
    ]
    matches = evaluate_rule(rule, events)
    assert len(matches) == 1
    assert matches[0].eid == 1


def test_evaluator_exact_match_case_insensitive():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="security"),
        detection={"selection": {"TargetUserName": "Admin"}, "condition": "selection"},
        level="high", description="", tags=[], source_path=None)
    events = [_make_event("Security", 4624, {"TargetUserName": "admin"})]
    assert len(evaluate_rule(rule, events)) == 1


def test_evaluator_wildcard_match():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="sysmon"),
        detection={"selection": {"Image": "*mimikatz*"}, "condition": "selection"},
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Sysmon", 1, {"Image": r"C:\Temp\mimikatz.exe"}),
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\cmd.exe"}),
    ]
    assert len(evaluate_rule(rule, events)) == 1


def test_evaluator_contains_modifier():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="sysmon"),
        detection={"selection": {"CommandLine|contains": "whoami"}, "condition": "selection"},
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Sysmon", 1, {"CommandLine": "cmd /c whoami /all"}),
        _make_event("Sysmon", 1, {"CommandLine": "cmd /c ipconfig"}),
    ]
    assert len(evaluate_rule(rule, events)) == 1


def test_evaluator_endswith_modifier():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="sysmon"),
        detection={"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
        level="high", description="", tags=[], source_path=None)
    events = [_make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\cmd.exe"})]
    assert len(evaluate_rule(rule, events)) == 1


def test_evaluator_startswith_modifier():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="sysmon"),
        detection={"selection": {"Image|startswith": "C:\\Windows"}, "condition": "selection"},
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\cmd.exe"}),
        _make_event("Sysmon", 1, {"Image": r"C:\Temp\evil.exe"}),
    ]
    assert len(evaluate_rule(rule, events)) == 1


def test_evaluator_list_or():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="sysmon"),
        detection={"selection": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe"]}, "condition": "selection"},
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\cmd.exe"}),
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\powershell.exe"}),
        _make_event("Sysmon", 1, {"Image": r"C:\Temp\evil.exe"}),
    ]
    assert len(evaluate_rule(rule, events)) == 2


def test_evaluator_all_modifier():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="sysmon"),
        detection={"selection": {"CommandLine|contains|all": ["whoami", "/all"]}, "condition": "selection"},
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Sysmon", 1, {"CommandLine": "cmd /c whoami /all"}),
        _make_event("Sysmon", 1, {"CommandLine": "cmd /c whoami"}),
    ]
    assert len(evaluate_rule(rule, events)) == 1


def test_evaluator_and_within_selection():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="sysmon"),
        detection={"selection": {"Image|endswith": "\\cmd.exe", "CommandLine|contains": "whoami"}, "condition": "selection"},
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd /c whoami"}),
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd /c ipconfig"}),
    ]
    assert len(evaluate_rule(rule, events)) == 1


def test_evaluator_condition_and_not_filter():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="sysmon"),
        detection={
            "selection": {"Image|endswith": "\\svchost.exe"},
            "filter": {"ParentImage|endswith": "\\services.exe"},
            "condition": "selection and not filter",
        },
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\svchost.exe", "ParentImage": r"C:\Windows\System32\services.exe"}),
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\svchost.exe", "ParentImage": r"C:\Temp\evil.exe"}),
    ]
    matches = evaluate_rule(rule, events)
    assert len(matches) == 1
    assert matches[0].event_data["ParentImage"] == r"C:\Temp\evil.exe"


def test_evaluator_condition_or():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="sysmon"),
        detection={
            "selection_cmd": {"Image|endswith": "\\cmd.exe"},
            "selection_ps": {"Image|endswith": "\\powershell.exe"},
            "condition": "selection_cmd or selection_ps",
        },
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\cmd.exe"}),
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\powershell.exe"}),
        _make_event("Sysmon", 1, {"Image": r"C:\Temp\evil.exe"}),
    ]
    assert len(evaluate_rule(rule, events)) == 2


def test_evaluator_condition_1_of_selection():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="sysmon"),
        detection={
            "selection_a": {"Image|endswith": "\\cmd.exe"},
            "selection_b": {"Image|endswith": "\\powershell.exe"},
            "condition": "1 of selection*",
        },
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\cmd.exe"}),
        _make_event("Sysmon", 1, {"Image": r"C:\Temp\evil.exe"}),
    ]
    assert len(evaluate_rule(rule, events)) == 1


def test_evaluator_excludes_noise():
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    from artiforge.detectors.sigma_models import SigmaRule, LogSource
    rule = SigmaRule(title="Test", id=None,
        logsource=LogSource(product="windows", service="sysmon"),
        detection={"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
        level="high", description="", tags=[], source_path=None)
    events = [
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\cmd.exe"}, phase_id=0),
        _make_event("Sysmon", 1, {"Image": r"C:\Windows\System32\cmd.exe"}, phase_id=1),
    ]
    matches = evaluate_rule(rule, events)
    assert len(matches) == 1
    assert matches[0].phase_id == 1


# ── CLI integration tests ──────────────────────────────────────────────────────

from click.testing import CliRunner
from artiforge.cli import main


@pytest.fixture
def runner():
    return CliRunner()


def test_check_auto_discovers_sigma_rules(runner):
    result = runner.invoke(main, ["check", "--lab", "uc3", "--seed", "42"])
    assert result.exit_code == 0
    assert "Sigma rules" in result.output


def test_check_sigma_only(runner):
    result = runner.invoke(main, ["check", "--lab", "uc3", "--seed", "42", "--sigma-only"])
    assert result.exit_code == 0
    assert "Built-in rules" not in result.output
    assert "Sigma rules" in result.output


def test_check_sigma_dir(runner, tmp_path):
    _write_sigma(tmp_path, "rule.yml", _valid_sigma())
    result = runner.invoke(main, [
        "check", "--lab", "uc3", "--seed", "42",
        "--sigma-dir", str(tmp_path),
    ])
    assert result.exit_code == 0
    assert "Sigma rules" in result.output


def test_uc3_sigma_lolbin_fires():
    from artiforge.core import engine
    from artiforge.detectors.sigma_loader import load_sigma_dir
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    spec = engine.load_lab("uc3")
    bundle = engine.run(spec, seed=42)
    rules = load_sigma_dir(Path("artiforge/labs/uc3/sigma"))
    lolbin = [r for r in rules if "LOLBin" in r.title][0]
    matches = evaluate_rule(lolbin, bundle.events)
    assert len(matches) >= 1


def test_uc3_sigma_cloudflared_fires():
    from artiforge.core import engine
    from artiforge.detectors.sigma_loader import load_sigma_dir
    from artiforge.detectors.sigma_evaluator import evaluate_rule
    spec = engine.load_lab("uc3")
    bundle = engine.run(spec, seed=42)
    rules = load_sigma_dir(Path("artiforge/labs/uc3/sigma"))
    tunnel = [r for r in rules if "Cloudflared" in r.title][0]
    matches = evaluate_rule(tunnel, bundle.events)
    assert len(matches) >= 1
