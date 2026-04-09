"""ArtiForge CLI — IoC and artifact generator for cybersecurity training labs."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from artiforge.core import engine
from artiforge.exporters import elastic, xml_exporter

_SUPPORTED_EIDS = {
    "Security":    [
        4624, 4625, 4634, 4648, 4656, 4657, 4663, 4670, 4672,
        4688, 4698, 4720, 4723, 4724, 4725, 4726, 4732, 4768,
        4769, 4771, 4776, 4946, 4947, 5156, 5157,
    ],
    "System":      [7036, 7045],
    "Sysmon":      [1, 3, 5, 7, 8, 10, 11, 12, 13, 14, 17, 18, 22, 23, 25],
    "Application": [1],
    "PowerShell":  [4103, 4104],
    "WMI":         [5857, 5860, 5861],
}


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("artiforge")
    except Exception:
        return "0.1.0"


@click.group()
@click.version_option(
    version=_version(),
    prog_name="ArtiForge",
    message="%(prog)s v%(version)s  |  by D3vn0mi  |  MIT License",
)
def main():
    """ArtiForge — YAML-driven Windows event artifact generator for cybersecurity training labs.

    \b
    Built by D3vn0mi  |  https://github.com/D3vn0mi/ArtiForge
    """


# ── list-labs ─────────────────────────────────────────────────────────────────

# ── validate ──────────────────────────────────────────────────────────────────

@main.command("validate")
@click.option("--lab", default=None, help="Lab ID to validate (e.g. uc3)")
@click.option("--lab-path", default=None, type=click.Path(),
              help="Path to a lab.yaml outside the built-in labs directory")
@click.option("--strict", is_flag=True, default=False,
              help="Run additional realism checks (placeholder hashes, offset order, logon precedence)")
def validate(lab: str | None, lab_path: str | None, strict: bool):
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

    # ── Strict realism checks ─────────────────────────────────────────────────
    if strict:
        import re
        warnings: list[str] = []
        placeholder_re = re.compile(
            r'^(SHA256|SHA1|MD5)_HASH_OF_', re.IGNORECASE
        )

        for phase in spec.attack.phases:
            # 1. Placeholder hashes in fields
            for ev in phase.events:
                for field_name, val in ev.fields.items():
                    if isinstance(val, str) and placeholder_re.match(val):
                        warnings.append(
                            f"Phase {phase.id} EID {ev.eid}: "
                            f"field '{field_name}' still has a placeholder hash value"
                        )

            # 2. Offset monotonicity (offset_seconds going backwards)
            last_offset = -1
            for ev in phase.events:
                if ev.offset_seconds < last_offset:
                    warnings.append(
                        f"Phase {phase.id} EID {ev.eid}: "
                        f"offset_seconds {ev.offset_seconds} goes backwards "
                        f"(previous was {last_offset})"
                    )
                last_offset = ev.offset_seconds

        # 3. Logon-before-process-creation (run full bundle, check ordering)
        try:
            bundle = engine.run(spec, seed=0)
            host_first_logon: dict[str, object] = {}
            for ev in sorted(bundle.events, key=lambda e: e.timestamp):
                if ev.eid == 4624 and ev.phase_id != 0:
                    if ev.host not in host_first_logon:
                        host_first_logon[ev.host] = ev.timestamp
            for ev in bundle.events:
                if ev.eid == 4688 and ev.phase_id != 0:
                    logon_ts = host_first_logon.get(ev.host)
                    if logon_ts and ev.timestamp < logon_ts:
                        warnings.append(
                            f"Phase {ev.phase_id}: 4688 on {ev.host} at "
                            f"{ev.timestamp.strftime('%H:%M:%S')} occurs before "
                            f"first 4624 at "
                            f"{logon_ts.strftime('%H:%M:%S')}"  # type: ignore[union-attr]
                        )
        except Exception:
            pass  # strict check is advisory; don't abort on generator errors

        if warnings:
            click.echo(f"  Strict checks      WARN  ({len(warnings)} issue(s)):")
            for w in warnings:
                click.echo(f"    ⚠  {w}")
        else:
            click.echo(f"  Strict checks      OK")

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
@click.option(
    "--seed",
    default=None, type=int,
    help="RNG seed for deterministic generation (same seed → identical output)",
)
@click.option(
    "--jitter",
    default=0, type=int, show_default=True,
    help="Global timestamp jitter: each event timestamp is shifted ±N seconds randomly",
)
def generate(lab: str | None, lab_path: str | None, output: str, fmt: str,
             phases: str | None, base_time: str | None, dry_run: bool,
             seed: int | None, jitter: int):
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
        bundle = engine.run(
            spec,
            base_time_override=base_dt,
            phase_filter=phase_filter,
            seed=seed,
            jitter_seconds=jitter,
        )
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

    # ── Navigator layer (written whenever the lab has MITRE techniques)
    all_tids = [tid for p in spec.attack.phases for tid in p.mitre]
    if all_tids:
        import json as _json
        from artiforge.mitre.navigator import build_layer as _build_layer
        layer = _build_layer(spec)
        nav_path = run_dir / "navigator_layer.json"
        nav_path.write_text(_json.dumps(layer, indent=2), encoding="utf-8")
        written.append(nav_path)
        click.echo(f"  [mitre]   → {nav_path}  ({len(set(all_tids))} techniques)")

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



# ── navigator ─────────────────────────────────────────────────────────────────

@main.command("navigator")
@click.option("--lab", default=None, help="Lab ID (e.g. uc3)")
@click.option("--lab-path", default=None, type=click.Path(),
              help="Path to a lab.yaml outside the built-in labs directory")
@click.option("--output", "-o", default=None,
              help="Write layer JSON to file (default: <lab_id>_navigator_layer.json)")
def navigator(lab: str | None, lab_path: str | None, output: str | None):
    """Export a MITRE ATT&CK Navigator layer JSON for a lab."""
    if not lab and not lab_path:
        click.echo("Error: provide --lab <id> or --lab-path <path>", err=True)
        sys.exit(1)

    try:
        spec = engine.load_lab_from_path(Path(lab_path)) if lab_path else engine.load_lab(lab)
    except FileNotFoundError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    import json
    from artiforge.mitre.navigator import build_layer
    layer = build_layer(spec)

    all_tids = sorted({tid for p in spec.attack.phases for tid in p.mitre})
    out_path = Path(output) if output else Path(f"{spec.lab.id}_navigator_layer.json")
    out_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")

    click.echo(f"\n[ArtiForge] Navigator layer: {spec.lab.name}")
    click.echo(f"  {len(all_tids)} techniques  ·  {len(spec.attack.phases)} phases")
    click.echo(f"  Written to: {out_path.resolve()}")
    click.echo(f"\n  Open ATT&CK Navigator → Layer → Open Existing Layer → upload file\n")


# ── coverage ──────────────────────────────────────────────────────────────────

@main.command("coverage")
def coverage():
    """Print a MITRE ATT&CK coverage matrix across all built-in labs."""
    from artiforge.mitre.technique_names import TECHNIQUE_NAMES

    labs = engine.list_labs()
    lab_specs: list = []
    for lab_meta in labs:
        if "error" in lab_meta:
            continue
        try:
            lab_specs.append(engine.load_lab(lab_meta["id"]))
        except Exception:
            continue

    if not lab_specs:
        click.echo("No labs found.", err=True)
        sys.exit(1)

    # Collect all technique IDs and which labs cover them
    # tech_id → set of lab_ids
    coverage_map: dict[str, set[str]] = {}
    for spec in lab_specs:
        for phase in spec.attack.phases:
            for tid in phase.mitre:
                coverage_map.setdefault(tid, set()).add(spec.lab.id)

    if not coverage_map:
        click.echo("No MITRE techniques found in any lab.")
        return

    sorted_tids = sorted(coverage_map.keys())
    lab_ids = [s.lab.id for s in lab_specs]
    tid_w  = max(len(t) for t in sorted_tids)
    name_w = min(40, max(len(TECHNIQUE_NAMES.get(t, t)) for t in sorted_tids))

    header = f"  {'TECHNIQUE':<{tid_w}}  {'NAME':<{name_w}}"
    for lid in lab_ids:
        header += f"  {lid[:8]:>8}"
    click.echo(f"\n[ArtiForge] MITRE ATT&CK Coverage\n")
    click.echo(header)
    click.echo("  " + "─" * (tid_w + 2 + name_w + 2 + len(lab_ids) * 10))

    for tid in sorted_tids:
        name = TECHNIQUE_NAMES.get(tid, tid)
        if len(name) > name_w:
            name = name[:name_w - 1] + "…"
        row = f"  {tid:<{tid_w}}  {name:<{name_w}}"
        for lid in lab_ids:
            symbol = "  ●" if lid in coverage_map[tid] else "  ○"
            row += f"  {symbol:>8}"
        click.echo(row)

    total_labs_with_coverage = len({lid for lids in coverage_map.values() for lid in lids})
    click.echo(
        f"\n  ● covered  ○ not covered"
        f"  ·  {len(sorted_tids)} techniques across "
        f"{total_labs_with_coverage} lab(s)\n"
    )


# ── check ─────────────────────────────────────────────────────────────────────

@main.command("check")
@click.option("--lab", default=None, help="Lab ID (e.g. uc3)")
@click.option("--lab-path", default=None, type=click.Path(),
              help="Path to a lab.yaml outside the built-in labs directory")
@click.option("--seed", default=None, type=int,
              help="RNG seed for deterministic generation")
@click.option("--jitter", default=0, type=int,
              help="Global ±N second timestamp jitter")
def check(lab: str | None, lab_path: str | None, seed: int | None, jitter: int):
    """Run built-in detection rules against a generated bundle and report coverage."""
    if not lab and not lab_path:
        click.echo("Error: provide --lab <id> or --lab-path <path>", err=True)
        sys.exit(1)

    try:
        spec = engine.load_lab_from_path(Path(lab_path)) if lab_path else engine.load_lab(lab)
    except FileNotFoundError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    try:
        bundle = engine.run(spec, seed=seed, jitter_seconds=jitter)
    except Exception as exc:
        click.echo(f"Error during generation: {exc}", err=True)
        sys.exit(1)

    from artiforge.detectors import RULES, run_rules
    results = run_rules(bundle)
    attack_count = sum(1 for e in bundle.events if e.phase_id != 0)
    fired_count = sum(1 for r in results if r["fired"])

    click.echo(f"\n[ArtiForge] Checking lab: {spec.lab.name}")
    click.echo(f"  {len(RULES)} rules  ·  {attack_count} attack events  ·  {len(bundle.events)} total\n")

    id_w    = max(len(r["rule"].id)        for r in results)
    name_w  = max(len(r["rule"].name)      for r in results)
    tech_w  = max(len(r["rule"].technique) for r in results)

    for r in results:
        rule    = r["rule"]
        fired   = r["fired"]
        count   = len(r["matches"])
        status  = "FIRED" if fired else "NOT  "
        noun    = "event" if count == 1 else "events"
        click.echo(
            f"  {status}  {rule.id:<{id_w}}  "
            f"{rule.name:<{name_w}}  "
            f"{rule.technique:<{tech_w}}  "
            f"({count} {noun})"
        )

    pct = fired_count / len(RULES) * 100
    click.echo(f"\n  Coverage: {fired_count}/{len(RULES)} rules fired ({pct:.1f}%)")
    if fired_count == 0:
        click.echo("  ⚠  No rules fired — the attack chain may not be detectable.")
    elif fired_count == len(RULES):
        click.echo("  Lab covers all built-in detection techniques.")
    else:
        click.echo("  Lab is detectable. Add events to cover unfired rules.")
    click.echo()


# ── diff ──────────────────────────────────────────────────────────────────────

@main.command("diff")
@click.option("--lab",        default=None, help="First lab ID")
@click.option("--lab-path",   default=None, type=click.Path(), help="First lab YAML path")
@click.option("--other",      default=None, help="Second lab ID")
@click.option("--other-path", default=None, type=click.Path(), help="Second lab YAML path")
@click.option("--seed", default=None, type=int,
              help="RNG seed (same seed applied to both bundles for a fair comparison)")
def diff(lab: str | None, lab_path: str | None,
         other: str | None, other_path: str | None,
         seed: int | None):
    """Compare two labs — show how their generated bundles differ."""
    if not (lab or lab_path):
        click.echo("Error: provide --lab or --lab-path for the first lab", err=True)
        sys.exit(1)
    if not (other or other_path):
        click.echo("Error: provide --other or --other-path for the second lab", err=True)
        sys.exit(1)

    try:
        spec_a = engine.load_lab_from_path(Path(lab_path)) if lab_path else engine.load_lab(lab)
        spec_b = engine.load_lab_from_path(Path(other_path)) if other_path else engine.load_lab(other)
    except FileNotFoundError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    try:
        bundle_a = engine.run(spec_a, seed=seed)
        bundle_b = engine.run(spec_b, seed=seed)
    except Exception as exc:
        click.echo(f"Error during generation: {exc}", err=True)
        sys.exit(1)

    result = engine.compare_bundles(bundle_a, bundle_b)
    ta, tb = result["totals_a"], result["totals_b"]
    pa, pb = result["phases_a"], result["phases_b"]
    ea, eb = result["eids_a"],   result["eids_b"]

    def _delta(a: int, b: int) -> str:
        d = b - a
        return f"+{d}" if d > 0 else str(d) if d < 0 else "="

    name_a = result["lab_a"]
    name_b = result["lab_b"]
    col = max(len(name_a), len(name_b), 20)

    click.echo(f"\n[ArtiForge] Diff: {name_a}  vs  {name_b}\n")
    click.echo(f"  {'Metric':<28} {'A':>{col}}  {'B':>{col}}  {'Delta':>7}")
    click.echo("  " + "─" * (28 + col * 2 + 13))

    rows = [
        ("Total events",    ta["total"],  tb["total"]),
        ("  Attack events", ta["attack"], tb["attack"]),
        ("  Noise events",  ta["noise"],  tb["noise"]),
        ("File artifacts",  ta["files"],  tb["files"]),
    ]
    for label, a_val, b_val in rows:
        click.echo(f"  {label:<28} {a_val:>{col}}  {b_val:>{col}}  {_delta(a_val, b_val):>7}")

    # Per-phase attack event counts
    all_phase_ids = sorted(set(list(pa.keys()) + list(pb.keys())))
    if all_phase_ids:
        click.echo(f"\n  {'Attack events by phase':<28} {'A':>{col}}  {'B':>{col}}  {'Delta':>7}")
        click.echo("  " + "─" * (28 + col * 2 + 13))
        for pid in all_phase_ids:
            pa_data = pa.get(pid, {"name": pb.get(pid, {}).get("name", f"Phase {pid}"), "events": 0})
            pb_data = pb.get(pid, {"name": pa.get(pid, {}).get("name", f"Phase {pid}"), "events": 0})
            label = f"  Phase {pid}  {pa_data['name'][:18]}"
            click.echo(
                f"  {label:<28} {pa_data['events']:>{col}}  {pb_data['events']:>{col}}  "
                f"{_delta(pa_data['events'], pb_data['events']):>7}"
            )

    # Per-EID counts (attack only, show EIDs present in either bundle)
    all_eids = sorted(set(list(ea.keys()) + list(eb.keys())))
    if all_eids:
        click.echo(f"\n  {'Attack events by EID':<28} {'A':>{col}}  {'B':>{col}}  {'Delta':>7}")
        click.echo("  " + "─" * (28 + col * 2 + 13))
        for eid in all_eids:
            a_c = ea.get(eid, 0)
            b_c = eb.get(eid, 0)
            click.echo(f"  {'  EID ' + str(eid):<28} {a_c:>{col}}  {b_c:>{col}}  {_delta(a_c, b_c):>7}")

    click.echo()


# ── graph ─────────────────────────────────────────────────────────────────────

@main.command("graph")
@click.option("--lab", default=None, help="Lab ID (e.g. uc3)")
@click.option("--lab-path", default=None, type=click.Path(),
              help="Path to a lab.yaml outside the built-in labs directory")
@click.option("--seed", default=None, type=int, help="RNG seed for deterministic generation")
def graph(lab: str | None, lab_path: str | None, seed: int | None):
    """Show the phase dependency graph — which events are correlated via GUID/LogonId."""
    if not lab and not lab_path:
        click.echo("Error: provide --lab <id> or --lab-path <path>", err=True)
        sys.exit(1)

    try:
        spec = engine.load_lab_from_path(Path(lab_path)) if lab_path else engine.load_lab(lab)
    except FileNotFoundError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    try:
        bundle = engine.run(spec, seed=seed)
    except Exception as exc:
        click.echo(f"Error during generation: {exc}", err=True)
        sys.exit(1)

    # Collect correlation fields: ProcessGuid → list of events, LogonId → list of events
    attack_events = [e for e in bundle.events if e.phase_id != 0]

    # Build maps: guid/logon_id → events that produce it (Sysmon 1 → ProcessGuid)
    #             guid/logon_id → events that consume it (Sysmon 3/5/... → ProcessGuid)
    guid_producers:  dict[str, list] = {}
    guid_consumers:  dict[str, list] = {}
    logon_producers: dict[str, list] = {}
    logon_consumers: dict[str, list] = {}

    for ev in attack_events:
        ed = ev.event_data
        # ProcessGuid: produced by Sysmon 1, consumed by Sysmon 3/5/7/8/10/...
        if ev.eid == 1 and ev.channel == "Sysmon":
            guid = ed.get("ProcessGuid", "")
            if guid:
                guid_producers.setdefault(guid, []).append(ev)
        elif ev.channel == "Sysmon":
            for key in ("ProcessGuid", "ParentProcessGuid", "SourceProcessGuid",
                        "TargetProcessGuid"):
                guid = ed.get(key, "")
                if guid:
                    guid_consumers.setdefault(guid, []).append(ev)

        # LogonId: produced by 4624/4648, consumed by 4688/4672/...
        if ev.eid in (4624, 4648):
            lid = ed.get("TargetLogonId", ed.get("SubjectLogonId", ""))
            if lid and lid not in ("0x0", "0x3e7", "0x3e4"):
                logon_producers.setdefault(lid, []).append(ev)
        elif ev.eid in (4688, 4672, 4698, 4634):
            for key in ("SubjectLogonId", "TargetLogonId"):
                lid = ed.get(key, "")
                if lid and lid not in ("0x0", "0x3e7", "0x3e4"):
                    logon_consumers.setdefault(lid, []).append(ev)

    def _ev_label(ev) -> str:
        desc = ev.event_data.get("Image", ev.event_data.get("TargetUserName",
               ev.event_data.get("ServiceName", "")))
        short = desc.split("\\")[-1] if desc else ""
        tag = f"  [{short}]" if short else ""
        return f"[Ph{ev.phase_id}] EID {ev.eid} on {ev.host}{tag}"

    click.echo(f"\n[ArtiForge] Dependency graph: {spec.lab.name}\n")

    # ProcessGuid chains
    all_guids = set(list(guid_producers.keys()) + list(guid_consumers.keys()))
    shown_guid = False
    for guid in all_guids:
        producers = guid_producers.get(guid, [])
        consumers = guid_consumers.get(guid, [])
        if not producers and not consumers:
            continue
        shown_guid = True
        short_guid = guid[:13] + "…" if len(guid) > 14 else guid
        click.echo(f"  ProcessGuid {short_guid}")
        for ev in producers:
            click.echo(f"    ├─ PRODUCES: {_ev_label(ev)}")
        for ev in consumers:
            click.echo(f"    └─ CONSUMES: {_ev_label(ev)}")

    if shown_guid:
        click.echo()

    # LogonId chains
    all_lids = set(list(logon_producers.keys()) + list(logon_consumers.keys()))
    for lid in sorted(all_lids):
        producers = logon_producers.get(lid, [])
        consumers = logon_consumers.get(lid, [])
        if not producers and not consumers:
            continue
        click.echo(f"  LogonId {lid}")
        for ev in producers:
            click.echo(f"    ├─ PRODUCES: {_ev_label(ev)}")
        for ev in consumers:
            click.echo(f"    └─ CONSUMES: {_ev_label(ev)}")

    if not all_guids and not all_lids:
        click.echo("  No ProcessGuid or LogonId correlations found in attack events.")

    click.echo()


# ── serve ─────────────────────────────────────────────────────────────────────

def _in_docker() -> bool:
    """Return True when running inside a Docker container."""
    import os
    return os.path.exists("/.dockerenv")


@main.command("serve")
@click.option("--host", default=None,
              help="Interface to bind. Defaults to 0.0.0.0 inside Docker, 127.0.0.1 otherwise.")
@click.option("--port", default=5000, show_default=True, type=int,
              help="Port to listen on")
@click.option("--debug", is_flag=True, default=False, hidden=True,
              help="Enable Flask debug mode (development only)")
def serve(host: str | None, port: int, debug: bool):
    """Start the ArtiForge web UI.

    \b
    Local:  artiforge serve
            → http://localhost:5000

    Docker: docker run --rm -p 5000:5000 artiforge serve
            → http://localhost:5000  (on host browser)
    """
    try:
        from artiforge.web.app import app as flask_app
    except ImportError:
        click.echo(
            "Flask is required for the web UI.\n"
            "Install it with:  pip install artiforge[web]",
            err=True,
        )
        sys.exit(1)

    effective_host = host or ("0.0.0.0" if _in_docker() else "127.0.0.1")
    display_host   = "localhost" if effective_host in ("127.0.0.1", "0.0.0.0") else effective_host

    click.echo(f"\n[ArtiForge] Web UI")
    click.echo(f"  http://{display_host}:{port}")
    click.echo(f"  Press Ctrl+C to stop.\n")
    flask_app.run(host=effective_host, port=port, debug=debug)


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
