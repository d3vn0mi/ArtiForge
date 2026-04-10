"""ATT&CK Navigator layer builder.

Generates a JSON layer file compatible with the MITRE ATT&CK Navigator
(https://mitre-attack.github.io/attack-navigator/).

Usage:
    from artiforge.mitre.navigator import build_layer
    layer = build_layer(spec)           # returns dict
    Path("layer.json").write_text(json.dumps(layer, indent=2))
"""

from __future__ import annotations

from artiforge.core.models import LabSpec

# One distinct colour per phase (cycles for labs with >8 phases).
_PHASE_COLOURS = [
    "#e74c3c",  # red
    "#e67e22",  # orange
    "#f1c40f",  # yellow
    "#2ecc71",  # green
    "#3498db",  # blue
    "#9b59b6",  # purple
    "#1abc9c",  # teal
    "#e91e63",  # pink
]


def build_layer(spec: LabSpec) -> dict:
    """Return a Navigator v4.5 layer dict for the given lab spec.

    Each phase gets a distinct colour. Techniques that appear in multiple
    phases use the colour of the *last* phase that references them, and
    the comment lists all phases.
    """
    # phase_id → colour
    colour_map: dict[int, str] = {}
    for i, phase in enumerate(spec.attack.phases):
        colour_map[phase.id] = _PHASE_COLOURS[i % len(_PHASE_COLOURS)]

    # technique ID → {phases: [(id, name)], colour: str}
    tech_data: dict[str, dict] = {}
    for phase in spec.attack.phases:
        for tid in phase.mitre:
            if tid not in tech_data:
                tech_data[tid] = {"phases": [], "colour": colour_map[phase.id]}
            tech_data[tid]["phases"].append((phase.id, phase.name))
            tech_data[tid]["colour"] = colour_map[phase.id]  # last phase wins

    techniques = []
    for tid, data in tech_data.items():
        phase_lines = "; ".join(
            f"Phase {pid}: {pname}" for pid, pname in data["phases"]
        )
        # showSubtechniques=True for parent IDs (e.g. T1218), False for sub-techniques
        is_parent = "." not in tid
        techniques.append({
            "techniqueID":       tid,
            "tactic":            None,
            "color":             data["colour"],
            "comment":           phase_lines,
            "enabled":           True,
            "metadata":          [],
            "links":             [],
            "showSubtechniques": is_parent,
        })

    legend_items = [
        {
            "label": f"Phase {phase.id}: {phase.name}",
            "color": colour_map[phase.id],
        }
        for phase in spec.attack.phases
        if any(phase.mitre)
    ]

    return {
        "name":        spec.lab.name,
        "versions":    {"attack": spec.lab.mitre_version.lstrip("v"), "navigator": "5.1", "layer": "4.5"},
        "domain":      "enterprise-attack",
        "description": f"ArtiForge lab: {spec.lab.name}. {spec.lab.description}".strip(),
        "filters":     {"platforms": ["Windows"]},
        "sorting":     0,
        "layout": {
            "layout":                "side",
            "aggregateFunction":     "average",
            "showID":                True,
            "showName":              True,
            "showAggregateScores":   False,
            "countUnscored":         False,
        },
        "hideDisabled":                   False,
        "techniques":                     techniques,
        "gradient": {
            "colors":   ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems":                    legend_items,
        "metadata":                       [],
        "links":                          [],
        "showTacticRowBackground":        False,
        "tacticRowBackground":            "#dddddd",
        "selectTechniquesAcrossTactics":  True,
        "selectSubtechniquesWithParent":  False,
        "selectVisibleTechniques":        False,
    }
