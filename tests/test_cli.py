"""Tests for the Click CLI — commands, options, output structure."""

import json
import pytest
from pathlib import Path
from click.testing import CliRunner
from artiforge.cli import main


@pytest.fixture
def runner():
    return CliRunner()


# ── list-labs ─────────────────────────────────────────────────────────────────

def test_list_labs_exit_code(runner):
    result = runner.invoke(main, ["list-labs"])
    assert result.exit_code == 0


def test_list_labs_shows_uc3(runner):
    result = runner.invoke(main, ["list-labs"])
    assert "uc3" in result.output
    assert "Egg-Cellent" in result.output


def test_list_labs_shows_phase_and_event_count(runner):
    result = runner.invoke(main, ["list-labs"])
    assert "5" in result.output   # 5 phases
    assert "40" in result.output  # 40 events


# ── info ──────────────────────────────────────────────────────────────────────

def test_info_exit_code(runner):
    result = runner.invoke(main, ["info", "--lab", "uc3"])
    assert result.exit_code == 0


def test_info_shows_hosts(runner):
    result = runner.invoke(main, ["info", "--lab", "uc3"])
    assert "WIN-WS1" in result.output
    assert "WIN-BACKUP1" in result.output
    assert "WIN-WS2" in result.output


def test_info_shows_all_phases(runner):
    result = runner.invoke(main, ["info", "--lab", "uc3"])
    for name in ["Initial Access", "Persistence", "Veeam", "Cloudflared", "Lateral"]:
        assert name in result.output


def test_info_shows_totals(runner):
    result = runner.invoke(main, ["info", "--lab", "uc3"])
    assert "40" in result.output   # total events
    assert "5" in result.output    # total file artifacts


def test_info_unknown_lab_fails(runner):
    result = runner.invoke(main, ["info", "--lab", "nonexistent_xyz"])
    assert result.exit_code != 0


# ── generate ─────────────────────────────────────────────────────────────────

def test_generate_creates_output_dir(runner, tmp_path):
    result = runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path)])
    assert result.exit_code == 0
    run_dirs = list(tmp_path.glob("uc3_*"))
    assert len(run_dirs) == 1


def test_generate_creates_events_dir(runner, tmp_path):
    runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path)])
    run_dir = next(tmp_path.glob("uc3_*"))
    assert (run_dir / "events").is_dir()


def test_generate_creates_elastic_dir(runner, tmp_path):
    runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path)])
    run_dir = next(tmp_path.glob("uc3_*"))
    assert (run_dir / "elastic" / "bulk_import.ndjson").exists()


def test_generate_creates_files_dir(runner, tmp_path):
    runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path)])
    run_dir = next(tmp_path.glob("uc3_*"))
    assert (run_dir / "files").is_dir()


def test_generate_creates_import_md(runner, tmp_path):
    runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path)])
    run_dir = next(tmp_path.glob("uc3_*"))
    assert (run_dir / "IMPORT.md").exists()


def test_generate_xml_format_only(runner, tmp_path):
    runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path),
                          "--format", "xml"])
    run_dir = next(tmp_path.glob("uc3_*"))
    assert (run_dir / "events").is_dir()
    assert not (run_dir / "elastic").exists()


def test_generate_elastic_format_only(runner, tmp_path):
    runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path),
                          "--format", "elastic"])
    run_dir = next(tmp_path.glob("uc3_*"))
    assert (run_dir / "elastic" / "bulk_import.ndjson").exists()
    assert not (run_dir / "events").exists()


def test_generate_selective_phases(runner, tmp_path):
    result = runner.invoke(main, ["generate", "--lab", "uc3",
                                   "--output", str(tmp_path),
                                   "--phases", "1"])
    assert result.exit_code == 0
    assert "9 events" in result.output


def test_generate_custom_base_time(runner, tmp_path):
    result = runner.invoke(main, ["generate", "--lab", "uc3",
                                   "--output", str(tmp_path),
                                   "--base-time", "2026-03-15T08:00:00Z"])
    assert result.exit_code == 0
    run_dir = next(tmp_path.glob("uc3_20260315_*"))
    assert run_dir.exists()


def test_generate_invalid_phase_filter(runner, tmp_path):
    result = runner.invoke(main, ["generate", "--lab", "uc3",
                                   "--output", str(tmp_path),
                                   "--phases", "abc"])
    assert result.exit_code != 0


def test_generate_unknown_lab_fails(runner, tmp_path):
    result = runner.invoke(main, ["generate", "--lab", "nonexistent_xyz",
                                   "--output", str(tmp_path)])
    assert result.exit_code != 0


def test_generate_output_mentions_event_count(runner, tmp_path):
    result = runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path)])
    assert "40 events" in result.output


def test_generate_ndjson_valid(runner, tmp_path):
    runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path)])
    run_dir = next(tmp_path.glob("uc3_*"))
    ndjson = (run_dir / "elastic" / "bulk_import.ndjson").read_text()
    for line in ndjson.strip().splitlines():
        json.loads(line)   # raises if invalid


def test_generate_dry_run_no_files(runner, tmp_path):
    result = runner.invoke(main, ["generate", "--lab", "uc3",
                                   "--output", str(tmp_path), "--dry-run"])
    assert result.exit_code == 0
    assert "dry-run" in result.output.lower()
    assert "no files written" in result.output.lower()
    assert list(tmp_path.iterdir()) == []   # nothing written


def test_generate_dry_run_shows_summary(runner, tmp_path):
    result = runner.invoke(main, ["generate", "--lab", "uc3",
                                   "--output", str(tmp_path), "--dry-run"])
    assert "40" in result.output    # event count
    assert "T+" in result.output    # phase offsets shown


def test_generate_lab_path(runner, tmp_path):
    import os
    lab_yaml = os.path.join(os.path.dirname(__file__), "..", "artiforge", "labs", "uc3", "lab.yaml")
    result = runner.invoke(main, ["generate", "--lab-path", lab_yaml,
                                   "--output", str(tmp_path)])
    assert result.exit_code == 0
    assert len(list(tmp_path.glob("uc3_*"))) == 1


# ── validate ─────────────────────────────────────────────────────────────────

def test_validate_uc3_passes(runner):
    result = runner.invoke(main, ["validate", "--lab", "uc3"])
    assert result.exit_code == 0
    assert "valid" in result.output.lower()


def test_validate_unknown_lab_fails(runner):
    result = runner.invoke(main, ["validate", "--lab", "nonexistent_xyz"])
    assert result.exit_code != 0


def test_validate_no_args_fails(runner):
    result = runner.invoke(main, ["validate"])
    assert result.exit_code != 0


# ── schema ───────────────────────────────────────────────────────────────────

def test_schema_prints_json(runner):
    result = runner.invoke(main, ["schema"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert "properties" in parsed or "$defs" in parsed


def test_schema_writes_file(runner, tmp_path):
    out = tmp_path / "schema.json"
    result = runner.invoke(main, ["schema", "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    json.loads(out.read_text())   # must be valid JSON
