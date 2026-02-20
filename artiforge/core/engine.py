"""Lab loader and phase runner — the core orchestration layer."""

from __future__ import annotations

import importlib.resources
from datetime import datetime, timezone
from pathlib import Path

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


# ── Provider metadata ──────────────────────────────────────────────────────────

_PROVIDER = {
    "Security": ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}"),
    "System":   ("Microsoft-Windows-Eventlog",          "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"),
    "Sysmon":   ("Microsoft-Windows-Sysmon",            "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"),
    "Application": ("Application",                      "{00000000-0000-0000-0000-000000000000}"),
}


def _provider(channel: str) -> tuple[str, str]:
    return _PROVIDER.get(channel, (channel, "{00000000-0000-0000-0000-000000000000}"))


# ── Lab discovery ──────────────────────────────────────────────────────────────

def _labs_root() -> Path:
    """Return the path to the bundled labs directory."""
    return Path(__file__).parent.parent / "labs"


def list_labs() -> list[dict]:
    """Return metadata for all available labs."""
    result = []
    for yaml_path in sorted(_labs_root().glob("*/lab.yaml")):
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
) -> ArtifactBundle:
    """Generate all artifacts for a lab spec."""

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

            for repeat_idx in range(event_spec.repeat):
                ts = resolve(
                    phase_base,
                    0,
                    event_spec.offset_seconds + repeat_idx * event_spec.repeat_gap_seconds,
                )

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

    return bundle
