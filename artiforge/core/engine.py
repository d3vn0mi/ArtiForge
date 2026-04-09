"""Lab loader and phase runner — the core orchestration layer."""

from __future__ import annotations

import random as _random
import warnings as _warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

_CURRENT_SCHEMA_VERSION = "1"

import yaml

from artiforge.core.models import (
    ArtifactBundle,
    EventSpec,
    GeneratedEvent,
    GeneratedFile,
    Host,
    LabSpec,
    Phase,
    User,
)
from artiforge.core.timeline import parse_base_time, resolve
from artiforge.generators import dispatch_event, dispatch_file
from artiforge.generators import noise as _noise_gen


# ── Provider metadata ──────────────────────────────────────────────────────────

_PROVIDER = {
    "Security":    ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}"),
    "System":      ("Service Control Manager",             "{555908d1-a6d7-4695-8e1e-26931d2012f4}"),
    "Sysmon":      ("Microsoft-Windows-Sysmon",            "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"),
    "Application": ("Application",                         "{00000000-0000-0000-0000-000000000000}"),
    "PowerShell":  ("Microsoft-Windows-PowerShell",        "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"),
    "WMI":         ("Microsoft-Windows-WMI-Activity",      "{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}"),
}


def _provider(channel: str) -> tuple[str, str]:
    return _PROVIDER.get(channel, (channel, "{00000000-0000-0000-0000-000000000000}"))


# ── Lab discovery ──────────────────────────────────────────────────────────────

def _labs_root() -> Path:
    """Return the path to the bundled labs directory."""
    return Path(__file__).parent.parent / "labs"


def list_labs() -> list[dict]:
    """Return metadata for all available labs (excludes _template)."""
    result = []
    for yaml_path in sorted(_labs_root().glob("*/lab.yaml")):
        if yaml_path.parent.name.startswith("_"):
            continue
        try:
            raw = yaml.safe_load(yaml_path.read_text())
            spec = LabSpec.model_validate(raw)
            phase_count = len(spec.attack.phases)
            event_count = sum(
                e.repeat for p in spec.attack.phases for e in p.events
            )
            result.append({
                "id": spec.lab.id,
                "name": spec.lab.name,
                "description": spec.lab.description,
                "phases": phase_count,
                "events": event_count,
            })
        except Exception as exc:
            result.append({"id": yaml_path.parent.name, "error": str(exc)})
    return result


def load_lab(lab_id: str) -> LabSpec:
    """Parse and validate a lab YAML by its id."""
    yaml_path = _labs_root() / lab_id / "lab.yaml"
    if not yaml_path.exists():
        raise FileNotFoundError(f"Lab '{lab_id}' not found at {yaml_path}")
    raw = yaml.safe_load(yaml_path.read_text())
    return LabSpec.model_validate(raw)


def load_lab_from_path(path: Path) -> LabSpec:
    """Parse and validate a lab YAML from an explicit filesystem path."""
    if not path.exists():
        raise FileNotFoundError(f"Lab YAML not found: {path}")
    raw = yaml.safe_load(path.read_text())
    return LabSpec.model_validate(raw)


# ── Context resolution ─────────────────────────────────────────────────────────

def _resolve_host(spec: LabSpec, host_name: str) -> Host:
    hosts = spec.infrastructure.hosts
    if host_name not in hosts:
        raise ValueError(f"Host '{host_name}' not found in infrastructure. "
                         f"Available: {list(hosts)}")
    return hosts[host_name]


def _resolve_user(host: Host, username: str | None) -> User | None:
    if username is None:
        return host.users[0] if host.users else None
    return host.get_user(username)


# ── Phase runner ───────────────────────────────────────────────────────────────

def run(
    spec: LabSpec,
    base_time_override: datetime | None = None,
    phase_filter: list[int] | None = None,
    seed: int | None = None,
    jitter_seconds: int = 0,
) -> ArtifactBundle:
    """Generate all artifacts for a lab spec.

    Args:
        spec: Validated lab specification.
        base_time_override: Override the base_time from the YAML.
        phase_filter: Restrict generation to these phase IDs only.
        seed: RNG seed for deterministic generation. None = random each run.
        jitter_seconds: Global ±N second timestamp jitter applied to every event.
            Per-event jitter_seconds takes precedence when non-zero.
    """
    if spec.lab.lab_schema_version != _CURRENT_SCHEMA_VERSION:
        _warnings.warn(
            f"Lab '{spec.lab.id}' uses schema version {spec.lab.lab_schema_version!r}; "
            f"current engine expects {_CURRENT_SCHEMA_VERSION!r}. "
            "Some fields may be ignored or cause errors.",
            UserWarning,
            stacklevel=2,
        )

    if seed is not None:
        _random.seed(seed)

    base_time = base_time_override or parse_base_time(spec.attack.base_time)

    bundle = ArtifactBundle(
        lab_id=spec.lab.id,
        lab_name=spec.lab.name,
        base_time=base_time,
    )

    record_id = 1000

    phases = spec.attack.phases
    if phase_filter:
        phases = [p for p in phases if p.id in phase_filter]

    for phase in phases:
        phase_base = resolve(base_time, phase.offset_minutes)

        for event_spec in phase.events:
            # Resolve host
            host_name = event_spec.host or phase.host
            if not host_name:
                raise ValueError(
                    f"Phase {phase.id} event EID {event_spec.eid} has no host defined."
                )
            host = _resolve_host(spec, host_name)

            # Resolve user
            user_name = event_spec.user or phase.user
            user = _resolve_user(host, user_name)

            prov_name, prov_guid = _provider(event_spec.channel)
            if event_spec.provider:
                prov_name = event_spec.provider

            # Effective per-event jitter (event-level overrides global)
            ev_jitter = event_spec.jitter_seconds or jitter_seconds

            # Track cumulative offset separately so repeat_jitter applies
            # to each inter-event gap, not to the total from zero.
            cumulative_gap = event_spec.offset_seconds

            for repeat_idx in range(event_spec.repeat):
                if repeat_idx > 0:
                    interval = event_spec.repeat_gap_seconds
                    if event_spec.repeat_jitter_seconds:
                        interval += _random.randint(
                            -event_spec.repeat_jitter_seconds,
                            event_spec.repeat_jitter_seconds,
                        )
                    cumulative_gap += interval

                ts = resolve(phase_base, 0, cumulative_gap)

                # Apply timestamp jitter
                if ev_jitter:
                    ts = ts + timedelta(seconds=_random.randint(-ev_jitter, ev_jitter))

                event_data = dispatch_event(
                    channel=event_spec.channel,
                    eid=event_spec.eid,
                    fields=event_spec.fields,
                    host=host,
                    user=user,
                    spec=spec,
                    timestamp=ts,
                )

                bundle.events.append(
                    GeneratedEvent(
                        record_id=record_id,
                        timestamp=ts,
                        channel=event_spec.channel,
                        eid=event_spec.eid,
                        host=host.name,
                        computer=host.fqdn,
                        provider_name=prov_name,
                        provider_guid=prov_guid,
                        event_data=event_data,
                        phase_id=phase.id,
                        phase_name=phase.name,
                    )
                )
                record_id += 1

        # File artifacts
        for fa_spec in phase.file_artifacts:
            gen_file = dispatch_file(fa_spec, phase)
            if gen_file:
                bundle.files.append(gen_file)

    # Noise injection — only when not running a phase-filtered subset
    if not phase_filter and spec.attack.noise:
        for noise_spec in spec.attack.noise:
            host = _resolve_host(spec, noise_spec.host)
            noise_events = _noise_gen.generate(
                noise_spec=noise_spec,
                host=host,
                base_time=base_time,
                record_id_start=record_id,
            )
            bundle.events.extend(noise_events)
            record_id += len(noise_events)

    return bundle


# ── Bundle comparison ──────────────────────────────────────────────────────────

def compare_bundles(bundle_a: ArtifactBundle, bundle_b: ArtifactBundle) -> dict:
    """Return a structured diff of two ArtifactBundles.

    Returns a dict with keys:
      totals_a / totals_b — {total, attack, noise, files}
      phases_a / phases_b — {phase_id: {name, events}} for attack events
      eids_a   / eids_b   — {eid: count} for attack events only
      hosts_a  / hosts_b  — {host: count} for attack events only
    """
    def _totals(b: ArtifactBundle) -> dict:
        attack = [e for e in b.events if e.phase_id != 0]
        noise  = [e for e in b.events if e.phase_id == 0]
        return {
            "total":  len(b.events),
            "attack": len(attack),
            "noise":  len(noise),
            "files":  len(b.files),
        }

    def _by_phase(b: ArtifactBundle) -> dict:
        result: dict[int, dict] = {}
        for ev in b.events:
            if ev.phase_id == 0:
                continue
            if ev.phase_id not in result:
                result[ev.phase_id] = {"name": ev.phase_name, "events": 0}
            result[ev.phase_id]["events"] += 1
        return result

    def _by_eid(b: ArtifactBundle) -> dict:
        counts: dict[int, int] = {}
        for ev in b.events:
            if ev.phase_id != 0:
                counts[ev.eid] = counts.get(ev.eid, 0) + 1
        return counts

    def _by_host(b: ArtifactBundle) -> dict:
        counts: dict[str, int] = {}
        for ev in b.events:
            if ev.phase_id != 0:
                counts[ev.host] = counts.get(ev.host, 0) + 1
        return counts

    return {
        "totals_a":  _totals(bundle_a),
        "totals_b":  _totals(bundle_b),
        "phases_a":  _by_phase(bundle_a),
        "phases_b":  _by_phase(bundle_b),
        "eids_a":    _by_eid(bundle_a),
        "eids_b":    _by_eid(bundle_b),
        "hosts_a":   _by_host(bundle_a),
        "hosts_b":   _by_host(bundle_b),
        "lab_a":     bundle_a.lab_name,
        "lab_b":     bundle_b.lab_name,
    }
