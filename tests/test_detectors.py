"""Tests for the built-in detection rules (artiforge/detectors/)."""

import pytest
from artiforge.core import engine
from artiforge.detectors.rules import RULES, DetectionRule, run_rules


@pytest.fixture(scope="module")
def uc3_bundle():
    spec = engine.load_lab("uc3")
    return engine.run(spec, seed=0)


@pytest.fixture(scope="module")
def uc3n_bundle():
    spec = engine.load_lab("uc3n")
    return engine.run(spec, seed=0)


# ── Rule structure ─────────────────────────────────────────────────────────────

def test_rules_is_nonempty():
    assert len(RULES) > 0


def test_all_rules_have_id():
    for rule in RULES:
        assert rule.id.startswith("DR-")


def test_all_rules_have_technique():
    for rule in RULES:
        assert rule.technique.startswith("T")


def test_all_rules_have_callable_check():
    for rule in RULES:
        assert callable(rule.check)


def test_rule_ids_are_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


# ── run_rules return format ────────────────────────────────────────────────────

def test_run_rules_returns_one_result_per_rule(uc3_bundle):
    results = run_rules(uc3_bundle)
    assert len(results) == len(RULES)


def test_run_rules_result_has_required_keys(uc3_bundle):
    results = run_rules(uc3_bundle)
    for r in results:
        assert "rule" in r
        assert "fired" in r
        assert "matches" in r


def test_run_rules_fired_is_bool(uc3_bundle):
    results = run_rules(uc3_bundle)
    for r in results:
        assert isinstance(r["fired"], bool)


def test_run_rules_matches_is_list(uc3_bundle):
    results = run_rules(uc3_bundle)
    for r in results:
        assert isinstance(r["matches"], list)


def test_run_rules_fired_consistent_with_matches(uc3_bundle):
    """fired must be True iff matches is non-empty."""
    results = run_rules(uc3_bundle)
    for r in results:
        assert r["fired"] == bool(r["matches"])


# ── UC3 specific rule expectations ────────────────────────────────────────────

def test_dr001_fires_on_uc3(uc3_bundle):
    """UC3 uses ie4uinit.exe / msxsl.exe — DR-001 must fire."""
    results = {r["rule"].id: r for r in run_rules(uc3_bundle)}
    assert results["DR-001"]["fired"]


def test_dr002_fires_on_uc3(uc3_bundle):
    """UC3 creates a scheduled task (EID 4698) — DR-002 must fire."""
    results = {r["rule"].id: r for r in run_rules(uc3_bundle)}
    assert results["DR-002"]["fired"]


def test_dr003_fires_on_uc3(uc3_bundle):
    """UC3 installs a service (EID 7045) — DR-003 must fire."""
    results = {r["rule"].id: r for r in run_rules(uc3_bundle)}
    assert results["DR-003"]["fired"]


def test_dr004_fires_on_uc3(uc3_bundle):
    """UC3 has Sysmon 3 on port 9401 — DR-004 must fire."""
    results = {r["rule"].id: r for r in run_rules(uc3_bundle)}
    assert results["DR-004"]["fired"]


def test_dr006_fires_on_uc3(uc3_bundle):
    """UC3 has EID 4648 (explicit credential logon) — DR-006 must fire."""
    results = {r["rule"].id: r for r in run_rules(uc3_bundle)}
    assert results["DR-006"]["fired"]


def test_dr001_matches_only_attack_events(uc3_bundle):
    """No noise events (phase_id==0) should appear in DR-001 matches."""
    results = {r["rule"].id: r for r in run_rules(uc3_bundle)}
    for ev in results["DR-001"]["matches"]:
        assert ev.phase_id != 0


def test_run_rules_subset(uc3_bundle):
    """run_rules accepts a subset of rules."""
    subset = [r for r in RULES if r.id in ("DR-001", "DR-002")]
    results = run_rules(uc3_bundle, rules=subset)
    assert len(results) == 2
    ids = {r["rule"].id for r in results}
    assert ids == {"DR-001", "DR-002"}


# ── Noise events are excluded ──────────────────────────────────────────────────

def test_rules_exclude_noise_events(uc3n_bundle):
    """uc3n has background noise; none should appear in rule matches."""
    results = run_rules(uc3n_bundle)
    for r in results:
        for ev in r["matches"]:
            assert ev.phase_id != 0, (
                f"Rule {r['rule'].id} matched a noise event "
                f"(phase_id=0, eid={ev.eid})"
            )


def test_uc3n_same_fired_rules_as_uc3(uc3_bundle, uc3n_bundle):
    """uc3n uses the same attack chain — the same rules should fire."""
    fired_uc3  = {r["rule"].id for r in run_rules(uc3_bundle)  if r["fired"]}
    fired_uc3n = {r["rule"].id for r in run_rules(uc3n_bundle) if r["fired"]}
    assert fired_uc3 == fired_uc3n
