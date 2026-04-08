"""ArtiForge CLI — IoC and artifact generator for cybersecurity training labs."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from artiforge.core import engine
from artiforge.exporters import elastic, xml_exporter


@click.group()
@click.version_option(package_name="artiforge")
def main():
    """ArtiForge — generate realistic Windows event artifacts for training labs."""


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
@click.option("--lab", required=True, help="Lab ID to generate artifacts for (e.g. uc3)")
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
def generate(lab: str, output: str, fmt: str, phases: str | None, base_time: str | None):
    """Generate event log artifacts and file stubs for a lab scenario."""

    # Load lab
    try:
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

    # Run generation
    click.echo(f"\n[ArtiForge] Generating artifacts for lab: {spec.lab.name}")
    try:
        bundle = engine.run(spec, base_time_override=base_dt, phase_filter=phase_filter)
    except Exception as exc:
        click.echo(f"Error during generation: {exc}", err=True)
        raise

    # Resolve output directory
    timestamp_tag = bundle.base_time.strftime("%Y%m%d_%H%M%S")
    run_dir = Path(output) / f"{lab}_{timestamp_tag}"
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


if __name__ == "__main__":
    main()
