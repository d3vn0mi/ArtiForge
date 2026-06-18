"""Flask web application for the ArtiForge browser UI."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from flask import Flask, render_template, request

from artiforge.core import engine
from artiforge.detectors.rules import run_rules
from artiforge.mitre.technique_names import TECHNIQUE_NAMES

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _event_summary(ev) -> str:
    """Return a one-line human description of a GeneratedEvent."""
    ed = ev.event_data
    eid = ev.eid

    if eid == 1 and ev.channel == "Sysmon":
        img = ed.get("Image", "").split("\\")[-1]
        return f"Process: {img}"
    if eid == 3 and ev.channel == "Sysmon":
        return f"→ {ed.get('DestinationIp', '?')}:{ed.get('DestinationPort', '?')}"
    if eid == 5 and ev.channel == "Sysmon":
        return f"Terminated: {ed.get('Image', '').split(chr(92))[-1]}"
    if eid == 11 and ev.channel == "Sysmon":
        return f"File: {ed.get('TargetFilename', '')[-48:]}"
    if eid == 13 and ev.channel == "Sysmon":
        return f"Reg: {ed.get('TargetObject', '')[-48:]}"
    if eid == 22 and ev.channel == "Sysmon":
        return f"DNS: {ed.get('QueryName', '')}"
    if eid == 4624:
        return f"Logon: {ed.get('TargetUserName', '?')} (type {ed.get('LogonType', '?')})"
    if eid == 4625:
        return f"Failed logon: {ed.get('TargetUserName', '?')}"
    if eid == 4634:
        return f"Logoff: {ed.get('TargetUserName', '?')}"
    if eid == 4648:
        return f"Explicit creds: {ed.get('TargetUserName', '?')} → {ed.get('TargetServerName', '?')}"
    if eid == 4688:
        return f"New process: {ed.get('NewProcessName', '').split(chr(92))[-1]}"
    if eid == 4698:
        return f"Sched task: {ed.get('TaskName', '?')}"
    if eid == 4720:
        return f"New account: {ed.get('TargetUserName', '?')}"
    if eid == 7045:
        return f"New service: {ed.get('ServiceName', '?')}"
    if eid in (4103, 4104) and ev.channel == "PowerShell":
        text = ed.get("ScriptBlockText", ed.get("Payload", ""))
        return f"PS: {text[:60]}…" if len(text) > 60 else f"PS: {text}"

    # Fallback: first non-empty value
    first_val = next((v for v in ed.values() if v), "")
    return first_val[:64] if first_val else f"EID {eid}"


def _phase_colour(phase_id: int) -> str:
    colours = ["#e74c3c", "#e67e22", "#f1c40f", "#2ecc71", "#3498db",
               "#9b59b6", "#1abc9c", "#e91e63"]
    return colours[(phase_id - 1) % len(colours)] if phase_id > 0 else "#95a5a6"


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    labs = _load_lab_summaries()
    return render_template("index.html", labs=labs, now=datetime.now(timezone.utc))


def _load_lab_summaries() -> list[dict]:
    """Load rich summaries for all labs — hosts, techniques, phases, noise config."""
    from pathlib import Path

    result = []
    labs_root = Path(__file__).parent.parent / "labs"
    for yaml_path in sorted(labs_root.glob("*/lab.yaml")):
        if yaml_path.parent.name.startswith("_"):
            continue
        try:
            spec = engine.load_lab(yaml_path.parent.name)
            phases = spec.attack.phases
            event_count = sum(e.repeat for p in phases for e in p.events)
            techniques = sorted({tid for p in phases for tid in p.mitre})
            hosts = list(spec.infrastructure.hosts.keys())
            channels = sorted({e.channel for p in phases for e in p.events})

            # Noise summary
            has_noise = bool(spec.attack.noise)
            noise_profile = None
            if has_noise:
                profiles = [n.noise_profile for n in spec.attack.noise if n.noise_profile]
                noise_profile = profiles[0] if profiles else None

            # Forensic artifacts
            has_forensics = getattr(spec.attack, "forensic_artifacts", False)

            # Sigma rules
            sigma_dir = yaml_path.parent / "sigma"
            sigma_count = len(list(sigma_dir.glob("*.yml"))) if sigma_dir.is_dir() else 0

            # Timeline span
            time_span = 0
            if phases:
                time_span = max(p.offset_minutes for p in phases)

            result.append({
                "id": spec.lab.id,
                "name": spec.lab.name,
                "description": spec.lab.description,
                "phases": len(phases),
                "events": event_count,
                "hosts": hosts,
                "techniques": techniques,
                "channels": channels,
                "has_noise": has_noise,
                "noise_profile": noise_profile,
                "has_forensics": has_forensics,
                "sigma_count": sigma_count,
                "time_span": time_span,
                "domain": spec.infrastructure.domain,
            })
        except Exception as exc:
            result.append({"id": yaml_path.parent.name, "error": str(exc)})
    return result


@app.route("/lab/<lab_id>")
def lab_detail(lab_id: str):
    try:
        spec = engine.load_lab(lab_id)
    except FileNotFoundError:
        return render_template("error.html", message=f"Lab '{lab_id}' not found.",
                               now=datetime.now(timezone.utc)), 404

    seed  = request.args.get("seed",   None,  type=int)
    jitter = request.args.get("jitter", 0,     type=int)
    tab   = request.args.get("tab",    "timeline")

    bundle = engine.run(spec, seed=seed, jitter_seconds=jitter)
    attack_events = [e for e in bundle.events if e.phase_id != 0]
    noise_events  = [e for e in bundle.events if e.phase_id == 0]

    # Timeline: all events sorted by timestamp, with phase colour + summary
    timeline = [
        {
            "ts":       e.timestamp.strftime("%H:%M:%S"),
            "phase_id": e.phase_id,
            "phase":    e.phase_name or "Noise",
            "colour":   _phase_colour(e.phase_id),
            "host":     e.host,
            "channel":  e.channel,
            "eid":      e.eid,
            "summary":  _event_summary(e),
            "techniques": e.mitre_techniques,
        }
        for e in sorted(bundle.events, key=lambda e: e.timestamp)
    ]

    # Trainer dashboard: detection rule results
    rule_results = run_rules(bundle)
    fired_count = sum(1 for r in rule_results if r["fired"])

    # Phase summary
    phase_summary = []
    for phase in spec.attack.phases:
        count = sum(1 for e in attack_events if e.phase_id == phase.id)
        phase_summary.append({
            "id":     phase.id,
            "name":   phase.name,
            "mitre":  phase.mitre,
            "count":  count,
            "colour": _phase_colour(phase.id),
        })

    # All unique techniques in this lab
    all_tids = sorted({tid for p in spec.attack.phases for tid in p.mitre})

    return render_template(
        "lab.html",
        spec=spec,
        bundle=bundle,
        timeline=timeline,
        attack_count=len(attack_events),
        noise_count=len(noise_events),
        rule_results=rule_results,
        fired_count=fired_count,
        phase_summary=phase_summary,
        all_tids=all_tids,
        TECHNIQUE_NAMES=TECHNIQUE_NAMES,
        tab=tab,
        seed=seed,
        jitter=jitter,
        now=datetime.now(timezone.utc),
    )


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", message="Page not found.", now=datetime.now(timezone.utc)), 404
