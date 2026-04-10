"""Tests for the artiforge/mitre/ module — Navigator layer, technique names, coverage."""

import json
import pytest
from artiforge.core import engine
from artiforge.mitre.technique_names import TECHNIQUE_NAMES
from artiforge.mitre.navigator import build_layer, _PHASE_COLOURS


@pytest.fixture(scope="module")
def uc3_spec():
    return engine.load_lab("uc3")


@pytest.fixture(scope="module")
def uc3_layer(uc3_spec):
    return build_layer(uc3_spec)


# ── Technique names ───────────────────────────────────────────────────────────

def test_all_labs_use_v18():
    """All built-in labs should declare mitre_version v18."""
    from artiforge.core import engine
    for lab_id in ("uc3", "uc3n"):
        spec = engine.load_lab(lab_id)
        assert spec.lab.mitre_version == "v18", (
            f"Lab {lab_id} still on {spec.lab.mitre_version}"
        )


def test_default_mitre_version_is_v18():
    """LabMeta default should reflect the current ATT&CK version."""
    from artiforge.core.models import LabMeta
    meta = LabMeta(id="test", name="Test")
    assert meta.mitre_version == "v18"


V18_NEW_TECHNIQUES = [
    "T1059.010",   # AutoHotkey & AutoIT (v15)
    "T1218.015",   # Electron Applications (v15)
    "T1027.013",   # Encrypted/Encoded File (v15)
    "T1098.007",   # Additional Local or Domain Groups (v16)
    "T1204.004",   # Malicious Copy and Paste (v17)
    "T1036.011",   # Overwrite Process Arguments (v17)
    "T1678",       # Delay Execution (v18)
    "T1204.005",   # Malicious Library (v18)
]


def test_v18_techniques_present_in_dict():
    """Technique names added in ATT&CK v15-v18 should be in the mapping."""
    for tid in V18_NEW_TECHNIQUES:
        assert tid in TECHNIQUE_NAMES, f"Missing v15-v18 technique: {tid}"
        assert isinstance(TECHNIQUE_NAMES[tid], str) and TECHNIQUE_NAMES[tid]


def test_technique_names_nonempty():
    assert len(TECHNIQUE_NAMES) > 0


def test_technique_names_keys_start_with_T():
    for k in TECHNIQUE_NAMES:
        assert k.startswith("T"), f"Unexpected key: {k}"


def test_technique_names_values_are_strings():
    for v in TECHNIQUE_NAMES.values():
        assert isinstance(v, str) and v


def test_uc3_techniques_all_in_dict():
    """Every technique used in UC3 should be in TECHNIQUE_NAMES."""
    spec = engine.load_lab("uc3")
    for phase in spec.attack.phases:
        for tid in phase.mitre:
            assert tid in TECHNIQUE_NAMES, f"Missing technique name for {tid}"


# ── Navigator layer structure ─────────────────────────────────────────────────

def test_layer_has_required_keys(uc3_layer):
    for key in ("name", "versions", "domain", "techniques", "legendItems",
                "filters", "layout", "gradient"):
        assert key in uc3_layer, f"Missing key: {key}"


def test_layer_name_matches_lab(uc3_layer, uc3_spec):
    assert uc3_layer["name"] == uc3_spec.lab.name


def test_layer_domain_is_enterprise(uc3_layer):
    assert uc3_layer["domain"] == "enterprise-attack"


def test_layer_versions_present(uc3_layer):
    v = uc3_layer["versions"]
    assert "attack" in v
    assert "navigator" in v
    assert "layer" in v


def test_layer_navigator_version_is_current(uc3_layer):
    """Navigator version in layer output should be 5.1 (compatible with ATT&CK v18)."""
    assert uc3_layer["versions"]["navigator"] == "5.1"


def test_layer_techniques_nonempty(uc3_layer):
    assert len(uc3_layer["techniques"]) > 0


def test_layer_techniques_have_required_fields(uc3_layer):
    for tech in uc3_layer["techniques"]:
        assert "techniqueID" in tech
        assert "color" in tech
        assert "comment" in tech
        assert "enabled" in tech


def test_layer_technique_ids_match_lab(uc3_layer, uc3_spec):
    layer_ids = {t["techniqueID"] for t in uc3_layer["techniques"]}
    yaml_ids  = {tid for p in uc3_spec.attack.phases for tid in p.mitre}
    assert layer_ids == yaml_ids


def test_layer_each_phase_has_colour(uc3_layer, uc3_spec):
    """Every phase that has techniques should appear in legendItems."""
    phases_with_techniques = [p for p in uc3_spec.attack.phases if p.mitre]
    legend_labels = {item["label"] for item in uc3_layer["legendItems"]}
    for phase in phases_with_techniques:
        assert any(f"Phase {phase.id}" in label for label in legend_labels)


def test_layer_colours_are_valid_hex(uc3_layer):
    import re
    hex_re = re.compile(r"^#[0-9a-fA-F]{6}$")
    for tech in uc3_layer["techniques"]:
        assert hex_re.match(tech["color"]), f"Bad colour: {tech['color']}"


def test_layer_parent_technique_shows_subtechniques(uc3_layer):
    """A parent ID (no dot) should have showSubtechniques=True."""
    for tech in uc3_layer["techniques"]:
        if "." not in tech["techniqueID"]:
            assert tech["showSubtechniques"] is True


def test_layer_sub_technique_no_show_subtechniques(uc3_layer):
    """A sub-technique (has dot) should have showSubtechniques=False."""
    for tech in uc3_layer["techniques"]:
        if "." in tech["techniqueID"]:
            assert tech["showSubtechniques"] is False


def test_layer_comment_includes_phase_name(uc3_layer, uc3_spec):
    """Each technique's comment should reference at least one phase name."""
    phase_names = {p.name for p in uc3_spec.attack.phases}
    for tech in uc3_layer["techniques"]:
        assert any(name in tech["comment"] for name in phase_names), (
            f"Technique {tech['techniqueID']} comment missing phase name"
        )


def test_uc3_layer_attack_version_is_18():
    """UC3 Navigator layer should reflect ATT&CK v18."""
    spec = engine.load_lab("uc3")
    layer = build_layer(spec)
    assert layer["versions"]["attack"] == "18"
    assert layer["versions"]["navigator"] == "5.1"
    assert layer["versions"]["layer"] == "4.5"


def test_layer_is_json_serialisable(uc3_layer):
    dumped = json.dumps(uc3_layer)
    reloaded = json.loads(dumped)
    assert reloaded["name"] == uc3_layer["name"]


# ── mitre_techniques on GeneratedEvent ────────────────────────────────────────

def test_generated_events_have_mitre_techniques():
    spec   = engine.load_lab("uc3")
    bundle = engine.run(spec, seed=0)
    attack = [e for e in bundle.events if e.phase_id != 0]
    # Every attack event should carry the techniques from its phase
    assert all(isinstance(e.mitre_techniques, list) for e in attack)


def test_attack_events_mitre_techniques_nonempty():
    spec   = engine.load_lab("uc3")
    bundle = engine.run(spec, seed=0)
    attack = [e for e in bundle.events if e.phase_id != 0]
    assert all(len(e.mitre_techniques) > 0 for e in attack)


def test_noise_events_have_no_mitre_techniques():
    spec   = engine.load_lab("uc3n")
    bundle = engine.run(spec, seed=0)
    noise  = [e for e in bundle.events if e.phase_id == 0]
    assert all(e.mitre_techniques == [] for e in noise)


def test_mitre_techniques_match_phase_mitre():
    spec   = engine.load_lab("uc3")
    bundle = engine.run(spec, seed=0)
    # Build phase_id → mitre from spec
    phase_mitre = {p.id: set(p.mitre) for p in spec.attack.phases}
    for ev in bundle.events:
        if ev.phase_id != 0:
            assert set(ev.mitre_techniques) == phase_mitre[ev.phase_id]


# ── ECS threat.* fields in elastic export ─────────────────────────────────────

def test_ecs_threat_field_present_for_attack_events():
    import json as _json
    from artiforge.exporters import elastic
    spec   = engine.load_lab("uc3")
    bundle = engine.run(spec, seed=0)

    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as tmp:
        ndjson_path = elastic.export(bundle, pathlib.Path(tmp))
        lines = ndjson_path.read_text().splitlines()

    # Even-indexed lines are action lines; odd-indexed are documents
    docs = [_json.loads(lines[i]) for i in range(1, len(lines), 2)]
    attack_docs = [d for d in docs if d.get("artiforge", {}).get("phase_id", 0) != 0]

    assert len(attack_docs) > 0
    for doc in attack_docs:
        assert "threat" in doc, "Missing threat field in attack event"
        assert doc["threat"]["framework"] == "MITRE ATT&CK"
        assert "id"   in doc["threat"]["technique"]
        assert "name" in doc["threat"]["technique"]


def test_ecs_threat_field_absent_for_noise_events():
    import json as _json
    from artiforge.exporters import elastic
    spec   = engine.load_lab("uc3n")
    bundle = engine.run(spec, seed=0)

    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as tmp:
        ndjson_path = elastic.export(bundle, pathlib.Path(tmp))
        lines = ndjson_path.read_text().splitlines()

    docs = [_json.loads(lines[i]) for i in range(1, len(lines), 2)]
    noise_docs = [d for d in docs if d.get("artiforge", {}).get("phase_id", 0) == 0]

    assert len(noise_docs) > 0
    for doc in noise_docs:
        assert "threat" not in doc, "Noise event should not have threat field"
