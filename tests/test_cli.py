"""Tests for the Click CLI — commands, options, output structure."""

import json
import pytest
from pathlib import Path
from click.testing import CliRunner
from cli import main


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
    assert "37" in result.output  # 37 events


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
    assert "37" in result.output   # total events
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
    assert "8 events" in result.output


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
    assert "37 events" in result.output


def test_generate_ndjson_valid(runner, tmp_path):
    runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path)])
    run_dir = next(tmp_path.glob("uc3_*"))
    ndjson = (run_dir / "elastic" / "bulk_import.ndjson").read_text()
    for line in ndjson.strip().splitlines():
        json.loads(line)   # raises if invalid
