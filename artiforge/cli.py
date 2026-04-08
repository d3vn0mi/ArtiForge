"""ArtiForge CLI — IoC and artifact generator for cybersecurity training labs."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from artiforge.core import engine
from artiforge.exporters import elastic, xml_exporter

_SUPPORTED_EIDS = {
    "Security":    [4624, 4625, 4634, 4648, 4672, 4688, 4698, 4720, 4732, 4776],
    "System":      [7036, 7045],
    "Sysmon":      [1, 3, 11, 13, 22],
    "Application": [1],
    "PowerShell":  [4103, 4104],
}


@click.group()
@click.version_option(package_name="artiforge")
def main():
    """ArtiForge — generate realistic Windows event artifacts for training labs."""


# ── list-labs ─────────────────────────────────────────────────────────────────

# ── validate ──────────────────────────────────────────────────────────────────

@main.command("validate")
@click.option("--lab", default=None, help="Lab ID to validate (e.g. uc3)")
@click.option("--lab-path", default=None, type=click.Path(),
              help="Path to a lab.yaml outside the built-in labs directory")
def validate(lab: str | None, lab_path: str | None):
    """Validate a lab YAML — schema check + generator dry-run."""
    if not lab and not lab_path:
        click.echo("Error: provide --lab <id> or --lab-path <path>", err=True)
        sys.exit(1)

    # Load
    try:
        if lab_path:
            spec = engine.load_lab_from_path(Path(lab_path))
        else:
            spec = engine.load_lab(lab)
    except FileNotFoundError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"  Schema validation FAILED:\n    {exc}", err=True)
        sys.exit(1)

    name = spec.lab.name
    phase_count = len(spec.attack.phases)
    event_count = sum(sum(e.repeat for e in p.events) for p in spec.attack.phases)
    file_count = sum(len(p.file_artifacts) for p in spec.attack.phases)

    click.echo(f"\n[ArtiForge] Validating: {name}")
    click.echo(f"  YAML syntax        OK")
    click.echo(f"  Schema validation  OK  ({phase_count} phases, {event_count} events, {file_count} file artifacts)")

    # Generator dry-run (phase 1 only — catches missing EIDs fast)
    try:
        engine.run(spec, phase_filter=[spec.attack.phases[0].id])
        click.echo(f"  Generator dry-run  OK  (phase {spec.attack.phases[0].id} tested)")
    except Exception as exc:
        click.echo(f"  Generator dry-run  FAILED:")
        click.echo(f"    {exc}")
        # Give a helpful hint if it's a missing EID
        msg = str(exc)
        for channel, eids in _SUPPORTED_EIDS.items():
            if f"{channel} EID" in msg or f"channel '{channel}'" in msg.lower():
                click.echo(f"  Supported {channel} EIDs: {eids}")
        sys.exit(1)

    # Check all phases for unsupported EIDs without running them
    unsupported = []
    from artiforge.generators import _CHANNEL_MAP
    for phase in spec.attack.phases:
        for ev in phase.events:
            mod = _CHANNEL_MAP.get(ev.channel)
            if mod is None:
                unsupported.append(f"phase {phase.id}: unknown channel '{ev.channel}'")
            elif ev.eid not in mod._GENERATORS:
                supported = sorted(mod._GENERATORS.keys())
                unsupported.append(
                    f"phase {phase.id}: {ev.channel} EID {ev.eid} not implemented "
                    f"(supported: {supported})"
                )

    if unsupported:
        click.echo(f"  EID coverage check FAILED:")
        for u in unsupported:
            click.echo(f"    ✗ {u}")
        sys.exit(1)

    click.echo(f"  EID coverage check OK  (all EIDs implemented)")
    click.echo(f"\n[ArtiForge] Lab is valid. Run: artiforge generate --lab {spec.lab.id}\n")


# ── schema ─────────────────────────────────────────────────────────────────────

@main.command("schema")
@click.option("--output", "-o", default=None,
              help="Write schema to file (default: print to stdout)")
def schema(output: str | None):
    """Print the JSON Schema for lab.yaml (useful for IDE autocompletion)."""
    import json
    from artiforge.core.models import LabSpec
    schema_dict = LabSpec.model_json_schema()
    schema_json = json.dumps(schema_dict, indent=2)
    if output:
        Path(output).write_text(schema_json, encoding="utf-8")
        click.echo(f"Schema written to {output}")
    else:
        click.echo(schema_json)


# ── list-labs ─────────────────────────────────────────────────────────────────

@main.command("list-labs")
def list_labs():
    """List all available labs."""
    labs = engine.list_labs()
    if not labs:
        click.echo("No labs found.")
        return

    click.echo(f"\n{'ID':<12} {'NAME':<30} {'PHASES':>6} {'EVENTS':>7}   DESCRIPTION")
    click.echo("─" * 80)
    for lab in labs:
        if "error" in lab:
            click.echo(f"  {'ERROR':<10} {lab['id']:<30} — {lab['error']}", err=True)
        else:
            desc = lab.get("description", "")
            short_desc = (desc[:40] + "…") if len(desc) > 40 else desc
            click.echo(
                f"  {lab['id']:<10} {lab['name']:<30} "
                f"{lab['phases']:>6} {lab['events']:>7}   {short_desc}"
            )
    click.echo()


# ── info ──────────────────────────────────────────────────────────────────────

@main.command("info")
@click.option("--lab", required=True, help="Lab ID (e.g. uc3)")
def info(lab: str):
    """Show detailed information about a lab."""
    try:
        spec = engine.load_lab(lab)
    except FileNotFoundError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"\n{'='*60}")
    click.echo(f"  {spec.lab.name}")
    click.echo(f"  ID: {spec.lab.id}  |  MITRE: {spec.lab.mitre_version}")
    click.echo(f"{'='*60}")
    click.echo(f"  {spec.lab.description}")
    click.echo()

    click.echo("  Infrastructure:")
    click.echo(f"    Domain: {spec.infrastructure.domain}")
    for name, host in spec.infrastructure.hosts.items():
        click.echo(f"    {name:<15} {host.ip:<16} {host.os}")

    click.echo()
    click.echo("  Attack Phases:")
    click.echo(f"  {'#':<4} {'OFFSET':>8}  {'EVENTS':>6}  {'FILES':>5}  NAME")
    click.echo("  " + "─" * 56)

    for phase in spec.attack.phases:
        total_events = sum(e.repeat for e in phase.events)
        click.echo(
            f"  {phase.id:<4} T+{phase.offset_minutes:>4}m  "
            f"{total_events:>6}  {len(phase.file_artifacts):>5}  {phase.name}"
        )

    total_ev = sum(sum(e.repeat for e in p.events) for p in spec.attack.phases)
    total_fi = sum(len(p.file_artifacts) for p in spec.attack.phases)
    click.echo(f"\n  Totals: {total_ev} events, {total_fi} file artifacts")
    click.echo(f"  Base time: {spec.attack.base_time}\n")


# ── generate ──────────────────────────────────────────────────────────────────

@main.command("generate")
@click.option("--lab", default=None, help="Lab ID to generate artifacts for (e.g. uc3)")
@click.option("--lab-path", default=None, type=click.Path(),
              help="Path to a lab.yaml outside the built-in labs directory")
@click.option(
    "--output", "-o",
    default="./artifacts",
    show_default=True,
    help="Output directory",
)
@click.option(
    "--format", "fmt",
    default="xml,elastic",
    show_default=True,
    help="Output formats: comma-separated list of xml, elastic",
)
@click.option(
    "--phases",
    default=None,
    help="Comma-separated phase IDs to generate (default: all). E.g. --phases 1,3,4",
)
@click.option(
    "--base-time",
    default=None,
    help="Override base timestamp (ISO format, e.g. 2026-02-19T09:12:00Z)",
)
@click.option(
    "--dry-run", is_flag=True, default=False,
    help="Preview what would be generated without writing any files",
)
def generate(lab: str | None, lab_path: str | None, output: str, fmt: str,
             phases: str | None, base_time: str | None, dry_run: bool):
    """Generate event log artifacts and file stubs for a lab scenario."""

    if not lab and not lab_path:
        click.echo("Error: provide --lab <id> or --lab-path <path>", err=True)
        sys.exit(1)

    # Load lab
    try:
        if lab_path:
            spec = engine.load_lab_from_path(Path(lab_path))
        else:
            spec = engine.load_lab(lab)
    except FileNotFoundError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    # Parse options
    formats = [f.strip().lower() for f in fmt.split(",")]
    phase_filter = None
    if phases:
        try:
            phase_filter = [int(p.strip()) for p in phases.split(",")]
        except ValueError:
            click.echo("Error: --phases must be comma-separated integers, e.g. 1,3,4", err=True)
            sys.exit(1)

    base_dt = None
    if base_time:
        try:
            base_dt = datetime.fromisoformat(base_time.replace("Z", "+00:00"))
        except ValueError:
            click.echo(f"Error: Cannot parse --base-time '{base_time}'. Use ISO format.", err=True)
            sys.exit(1)

    # Use spec lab id as the directory name (works whether --lab or --lab-path was used)
    lab_id = spec.lab.id

    # Run generation
    click.echo(f"\n[ArtiForge] Generating artifacts for lab: {spec.lab.name}")
    try:
        bundle = engine.run(spec, base_time_override=base_dt, phase_filter=phase_filter)
    except Exception as exc:
        click.echo(f"Error during generation: {exc}", err=True)
        raise

    # ── Dry-run: print summary and exit
    if dry_run:
        click.echo(f"\n  {'PHASE':<6} {'OFFSET':>8}  {'EVENTS':>7}  {'FILES':>6}  NAME")
        click.echo("  " + "─" * 55)
        for phase in spec.attack.phases:
            ev_count = sum(e.repeat for e in phase.events)
            fi_count = len(phase.file_artifacts)
            click.echo(
                f"  {phase.id:<6} T+{phase.offset_minutes:>4}m  "
                f"{ev_count:>7}  {fi_count:>6}  {phase.name}"
            )
        click.echo("  " + "─" * 55)
        total_ev = len(bundle.events)
        total_fi = len(bundle.files)
        ts_min = min(e.timestamp for e in bundle.events).strftime("%H:%M:%SZ")
        ts_max = max(e.timestamp for e in bundle.events).strftime("%H:%M:%SZ")
        click.echo(f"  Total:         {total_ev:>7}  {total_fi:>6}")
        click.echo(f"  Time span: {ts_min} → {ts_max}")
        timestamp_tag = bundle.base_time.strftime("%Y%m%d_%H%M%S")
        click.echo(f"  Would write to: {Path(output) / f'{lab_id}_{timestamp_tag}'}")
        click.echo(f"\n  (dry-run: no files written)\n")
        return

    # Resolve output directory
    timestamp_tag = bundle.base_time.strftime("%Y%m%d_%H%M%S")
    run_dir = Path(output) / f"{lab_id}_{timestamp_tag}"
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        click.echo(f"Error: Cannot create output directory '{run_dir}': {exc}", err=True)
        sys.exit(1)

    written: list[Path] = []

    # ── XML export
    if "xml" in formats:
        events_dir = run_dir / "events"
        xml_files = xml_exporter.export(bundle, events_dir)
        written.extend(xml_files)
        click.echo(f"  [xml]     → {events_dir}  ({len(xml_files)} files)")

    # ── Elastic export
    if "elastic" in formats:
        elastic_dir = run_dir / "elastic"
        ndjson = elastic.export(bundle, elastic_dir)
        written.append(ndjson)
        click.echo(f"  [elastic] → {ndjson}")

    # ── File artifacts
    if bundle.files:
        for gen_file in bundle.files:
            phase_dir = run_dir / "files" / f"phase{gen_file.phase_id:02d}"
            phase_dir.mkdir(parents=True, exist_ok=True)
            dest = phase_dir / gen_file.filename
            if gen_file.binary:
                dest.write_bytes(gen_file.content)
            else:
                dest.write_text(gen_file.content, encoding="utf-8")
            written.append(dest)
        file_count = len(bundle.files)
        click.echo(f"  [files]   → {run_dir / 'files'}  ({file_count} artifacts)")

    # ── Summary
    total_events = len(bundle.events)
    click.echo(f"\n  Summary: {total_events} events generated")
    click.echo(f"  Output:  {run_dir.resolve()}\n")

    # ── Write import instructions
    _write_import_md(run_dir, bundle, formats)

    click.echo(f"[ArtiForge] Done. See {run_dir / 'IMPORT.md'} for import instructions.\n")


def _write_import_md(run_dir: Path, bundle, formats: list[str]):
    lines = [
        f"# ArtiForge Import Guide",
        f"",
        f"**Lab:** {bundle.lab_name}  ",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  ",
        f"**Base time:** {bundle.base_time.strftime('%Y-%m-%dT%H:%M:%SZ')}  ",
        f"**Events:** {len(bundle.events)}  ",
        f"",
    ]

    if "elastic" in formats:
        lines += [
            "## Elasticsearch / Kibana",
            "",
            "```bash",
            "# 1. Upload via bulk API",
            f'curl -s -X POST "http://localhost:9200/_bulk" \\',
            f'  -H "Content-Type: application/x-ndjson" \\',
            f'  --data-binary @elastic/bulk_import.ndjson',
            "",
            "# 2. Or use Kibana Dev Tools → POST /_bulk with the NDJSON content",
            "```",
            "",
        ]

    if "xml" in formats:
        lines += [
            "## Windows Event Viewer / wevtutil",
            "",
            "The `events/` directory contains one XML file per (host, channel).",
            "Open directly in Windows Event Viewer via File → Open Saved Log,",
            "or import into a live log channel using `wevtutil im <file.xml>`.",
            "",
        ]

    if bundle.files:
        lines += [
            "## File Artifacts",
            "",
            "The `files/` directory contains staged artifacts to copy to VMs:",
            "",
        ]
        for f in bundle.files:
            lines.append(f"- **{f.filename}** → `{f.windows_dest}`")
        lines.append("")

    (run_dir / "IMPORT.md").write_text("\n".join(lines), encoding="utf-8")



# ── new-lab ───────────────────────────────────────────────────────────────────

@main.command("new-lab")
@click.option("--id", "lab_id", required=True,
              help="Lab ID: lowercase letters, digits, hyphens (e.g. uc4-rdp-pivot)")
@click.option("--name", "lab_name", default=None,
              help="Human-readable lab name (defaults to the lab ID)")
@click.option("--output", "-o", default=".",
              show_default=True,
              help="Parent directory to create the new lab folder in")
def new_lab(lab_id: str, lab_name: str | None, output: str):
    """Scaffold a new lab directory from the built-in template."""
    import re
    import shutil

    if not re.match(r'^[a-z0-9][a-z0-9-]*$', lab_id):
        click.echo(
            "Error: --id must be lowercase letters, digits, and hyphens, "
            "and must start with a letter or digit.",
            err=True,
        )
        sys.exit(1)

    display_name = lab_name or lab_id
    template_dir = Path(__file__).parent / "labs" / "_template"
    dest_dir = Path(output) / lab_id

    if dest_dir.exists():
        click.echo(f"Error: destination already exists: {dest_dir}", err=True)
        sys.exit(1)

    dest_dir.mkdir(parents=True)

    # Copy and patch lab.yaml
    template_yaml = (template_dir / "lab.yaml").read_text(encoding="utf-8")
    patched_yaml = template_yaml.replace(
        "  id: my-lab-id                  # FIXME: lowercase, hyphens allowed, e.g. \"uc4-rdp-pivot\"",
        f'  id: {lab_id}',
    ).replace(
        '  name: "My Lab Name"            # FIXME: human-readable, shown in artiforge list-labs',
        f'  name: "{display_name}"',
    )
    (dest_dir / "lab.yaml").write_text(patched_yaml, encoding="utf-8")

    # Copy DEVELOPMENT.md
    shutil.copy(template_dir / "DEVELOPMENT.md", dest_dir / "DEVELOPMENT.md")

    click.echo(f"\n[ArtiForge] Lab scaffolded: {dest_dir.resolve()}")
    click.echo(f"\n  Next steps:")
    click.echo(f"  1. Edit {dest_dir / 'lab.yaml'}")
    click.echo(f"     → Fill in every line marked FIXME")
    click.echo(f"  2. artiforge validate --lab-path {dest_dir / 'lab.yaml'}")
    click.echo(f"  3. artiforge generate --lab-path {dest_dir / 'lab.yaml'} --dry-run")
    click.echo(f"  4. artiforge generate --lab-path {dest_dir / 'lab.yaml'}\n")


if __name__ == "__main__":
    main()
