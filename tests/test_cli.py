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


# ── new-lab ───────────────────────────────────────────────────────────────────

def test_new_lab_creates_directory(runner, tmp_path):
    result = runner.invoke(main, ["new-lab", "--id", "test-lab", "--output", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / "test-lab").is_dir()


def test_new_lab_creates_lab_yaml(runner, tmp_path):
    runner.invoke(main, ["new-lab", "--id", "test-lab", "--output", str(tmp_path)])
    assert (tmp_path / "test-lab" / "lab.yaml").exists()


def test_new_lab_creates_development_md(runner, tmp_path):
    runner.invoke(main, ["new-lab", "--id", "test-lab", "--output", str(tmp_path)])
    assert (tmp_path / "test-lab" / "DEVELOPMENT.md").exists()


def test_new_lab_patches_id_in_yaml(runner, tmp_path):
    runner.invoke(main, ["new-lab", "--id", "my-scenario", "--output", str(tmp_path)])
    content = (tmp_path / "my-scenario" / "lab.yaml").read_text()
    assert "id: my-scenario" in content
    assert "my-lab-id" not in content


def test_new_lab_patches_name_in_yaml(runner, tmp_path):
    runner.invoke(main, ["new-lab", "--id", "my-scenario",
                          "--name", "Cool Attack Lab", "--output", str(tmp_path)])
    content = (tmp_path / "my-scenario" / "lab.yaml").read_text()
    assert "Cool Attack Lab" in content


def test_new_lab_default_name_is_id(runner, tmp_path):
    runner.invoke(main, ["new-lab", "--id", "my-scenario", "--output", str(tmp_path)])
    content = (tmp_path / "my-scenario" / "lab.yaml").read_text()
    assert 'name: "my-scenario"' in content


def test_new_lab_invalid_id_fails(runner, tmp_path):
    result = runner.invoke(main, ["new-lab", "--id", "My Bad ID!", "--output", str(tmp_path)])
    assert result.exit_code != 0


def test_new_lab_existing_dir_fails(runner, tmp_path):
    (tmp_path / "existing-lab").mkdir()
    result = runner.invoke(main, ["new-lab", "--id", "existing-lab", "--output", str(tmp_path)])
    assert result.exit_code != 0


def test_new_lab_shows_next_steps(runner, tmp_path):
    result = runner.invoke(main, ["new-lab", "--id", "test-lab", "--output", str(tmp_path)])
    assert "Next steps" in result.output
    assert "validate" in result.output


def test_list_labs_excludes_template(runner):
    result = runner.invoke(main, ["list-labs"])
    assert "_template" not in result.output
    assert "my-lab-id" not in result.output


# ── validate --strict ─────────────────────────────────────────────────────────

def test_validate_strict_uc3_passes(runner):
    result = runner.invoke(main, ["validate", "--lab", "uc3", "--strict"])
    assert result.exit_code == 0


def test_validate_strict_shows_strict_checks_line(runner):
    result = runner.invoke(main, ["validate", "--lab", "uc3", "--strict"])
    assert "Strict checks" in result.output


def test_validate_strict_ok_when_no_issues(runner):
    result = runner.invoke(main, ["validate", "--lab", "uc3", "--strict"])
    assert "OK" in result.output


def test_validate_strict_warns_placeholder_hashes(runner, tmp_path):
    """A lab.yaml with a SHA256_HASH_OF_* value triggers a strict warning."""
    src = Path(__file__).parent.parent / "artiforge" / "labs" / "uc3" / "lab.yaml"
    patched = tmp_path / "lab.yaml"
    content = src.read_text()
    # Inject a placeholder hash next to an existing field value.
    # "CommandLine: 'C:\Windows\System32\ie4uinit.exe -BaseSettings'" is line 121.
    content = content.replace(
        "CommandLine: 'C:\\Windows\\System32\\ie4uinit.exe -BaseSettings'",
        "CommandLine: 'C:\\Windows\\System32\\ie4uinit.exe -BaseSettings'\n"
        "            Hashes: SHA256_HASH_OF_PAYLOAD",
    )
    patched.write_text(content)
    result = runner.invoke(main, ["validate", "--lab-path", str(patched), "--strict"])
    assert "placeholder hash" in result.output.lower()


# ── check ─────────────────────────────────────────────────────────────────────

def test_check_exit_code(runner):
    result = runner.invoke(main, ["check", "--lab", "uc3", "--seed", "0"])
    assert result.exit_code == 0


def test_check_shows_rules(runner):
    result = runner.invoke(main, ["check", "--lab", "uc3", "--seed", "0"])
    assert "DR-001" in result.output
    assert "DR-004" in result.output


def test_check_shows_fired_and_not(runner):
    result = runner.invoke(main, ["check", "--lab", "uc3", "--seed", "0"])
    assert "FIRED" in result.output
    assert "NOT" in result.output


def test_check_shows_coverage_percentage(runner):
    result = runner.invoke(main, ["check", "--lab", "uc3", "--seed", "0"])
    assert "Coverage:" in result.output
    assert "%" in result.output


def test_check_no_args_fails(runner):
    result = runner.invoke(main, ["check"])
    assert result.exit_code != 0


def test_check_unknown_lab_fails(runner):
    result = runner.invoke(main, ["check", "--lab", "nonexistent_xyz"])
    assert result.exit_code != 0


def test_check_dr004_fires_on_uc3(runner):
    """UC3 has Sysmon 3 connections to port 9401 — DR-004 must fire."""
    result = runner.invoke(main, ["check", "--lab", "uc3", "--seed", "0"])
    # Find DR-004 line and verify it shows FIRED
    for line in result.output.splitlines():
        if "DR-004" in line:
            assert "FIRED" in line
            break
    else:
        pytest.fail("DR-004 line not found in check output")


# ── diff ──────────────────────────────────────────────────────────────────────

def test_diff_exit_code(runner):
    result = runner.invoke(main, ["diff", "--lab", "uc3", "--other", "uc3n", "--seed", "0"])
    assert result.exit_code == 0


def test_diff_shows_lab_names(runner):
    result = runner.invoke(main, ["diff", "--lab", "uc3", "--other", "uc3n", "--seed", "0"])
    assert "Egg-Cellent Resume" in result.output


def test_diff_shows_total_events(runner):
    result = runner.invoke(main, ["diff", "--lab", "uc3", "--other", "uc3n", "--seed", "0"])
    assert "Total events" in result.output


def test_diff_uc3_vs_uc3n_noise_delta(runner):
    """UC3N should have more total events than UC3 (noise injection)."""
    result = runner.invoke(main, ["diff", "--lab", "uc3", "--other", "uc3n", "--seed", "0"])
    assert "Noise events" in result.output
    # uc3n has noise; uc3 has none — delta should be positive
    for line in result.output.splitlines():
        if "Noise events" in line:
            # delta column should show a + value
            assert "+" in line
            break
    else:
        pytest.fail("'Noise events' line not found in diff output")


def test_diff_no_first_lab_fails(runner):
    result = runner.invoke(main, ["diff", "--other", "uc3n"])
    assert result.exit_code != 0


def test_diff_no_second_lab_fails(runner):
    result = runner.invoke(main, ["diff", "--lab", "uc3"])
    assert result.exit_code != 0


# ── graph ─────────────────────────────────────────────────────────────────────

def test_graph_exit_code(runner):
    result = runner.invoke(main, ["graph", "--lab", "uc3", "--seed", "0"])
    assert result.exit_code == 0


def test_graph_shows_lab_name(runner):
    result = runner.invoke(main, ["graph", "--lab", "uc3", "--seed", "0"])
    assert "Egg-Cellent Resume" in result.output


def test_graph_shows_process_or_logon_correlations(runner):
    result = runner.invoke(main, ["graph", "--lab", "uc3", "--seed", "0"])
    # UC3 has ProcessGuid correlations (Sysmon 1 → Sysmon 3/11) and LogonId links
    assert ("ProcessGuid" in result.output or "LogonId" in result.output
            or "No ProcessGuid" in result.output)


def test_graph_no_args_fails(runner):
    result = runner.invoke(main, ["graph"])
    assert result.exit_code != 0


# ── navigator ─────────────────────────────────────────────────────────────────

def test_navigator_exit_code(runner, tmp_path):
    out = tmp_path / "layer.json"
    result = runner.invoke(main, ["navigator", "--lab", "uc3", "--output", str(out)])
    assert result.exit_code == 0


def test_navigator_creates_json_file(runner, tmp_path):
    out = tmp_path / "layer.json"
    runner.invoke(main, ["navigator", "--lab", "uc3", "--output", str(out)])
    assert out.exists()


def test_navigator_output_is_valid_json(runner, tmp_path):
    out = tmp_path / "layer.json"
    runner.invoke(main, ["navigator", "--lab", "uc3", "--output", str(out)])
    data = json.loads(out.read_text())
    assert "techniques" in data
    assert "name" in data


def test_navigator_shows_technique_count(runner, tmp_path):
    out = tmp_path / "layer.json"
    result = runner.invoke(main, ["navigator", "--lab", "uc3", "--output", str(out)])
    assert "techniques" in result.output or "technique" in result.output.lower()


def test_navigator_no_args_fails(runner):
    result = runner.invoke(main, ["navigator"])
    assert result.exit_code != 0


def test_navigator_unknown_lab_fails(runner, tmp_path):
    out = tmp_path / "layer.json"
    result = runner.invoke(main, ["navigator", "--lab", "nonexistent_xyz",
                                   "--output", str(out)])
    assert result.exit_code != 0


# ── coverage ──────────────────────────────────────────────────────────────────

def test_coverage_exit_code(runner):
    result = runner.invoke(main, ["coverage"])
    assert result.exit_code == 0


def test_coverage_shows_technique_ids(runner):
    result = runner.invoke(main, ["coverage"])
    # UC3/UC3N both use T1572 (Protocol Tunneling)
    assert "T1572" in result.output


def test_coverage_shows_lab_ids(runner):
    result = runner.invoke(main, ["coverage"])
    assert "uc3" in result.output


def test_coverage_shows_filled_symbols(runner):
    result = runner.invoke(main, ["coverage"])
    assert "●" in result.output


def test_coverage_shows_empty_symbol_legend(runner):
    result = runner.invoke(main, ["coverage"])
    assert "○" in result.output


# ── generate writes navigator_layer.json ─────────────────────────────────────

def test_generate_writes_navigator_layer(runner, tmp_path):
    runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path)])
    run_dir = next(tmp_path.glob("uc3_*"))
    assert (run_dir / "navigator_layer.json").exists()


def test_generate_navigator_layer_is_valid(runner, tmp_path):
    runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path)])
    run_dir = next(tmp_path.glob("uc3_*"))
    data = json.loads((run_dir / "navigator_layer.json").read_text())
    assert data["domain"] == "enterprise-attack"
    assert len(data["techniques"]) > 0


def test_generate_output_mentions_mitre(runner, tmp_path):
    result = runner.invoke(main, ["generate", "--lab", "uc3", "--output", str(tmp_path)])
    assert "[mitre]" in result.output


# ── serve (Flask optional) ────────────────────────────────────────────────────

def test_serve_help(runner):
    result = runner.invoke(main, ["serve", "--help"])
    assert result.exit_code == 0
    assert "host" in result.output.lower() or "port" in result.output.lower()


# ── web UI routes ─────────────────────────────────────────────────────────────

pytest_flask = pytest.importorskip("flask", reason="Flask not installed")


@pytest.fixture
def web_client():
    from artiforge.web.app import app as flask_app
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


def test_web_index_returns_200(web_client):
    response = web_client.get("/")
    assert response.status_code == 200


def test_web_index_lists_labs(web_client):
    data = response = web_client.get("/")
    assert b"uc3" in response.data


def test_web_lab_detail_returns_200(web_client):
    response = web_client.get("/lab/uc3")
    assert response.status_code == 200


def test_web_lab_detail_shows_lab_name(web_client):
    response = web_client.get("/lab/uc3")
    assert b"Egg-Cellent" in response.data


def test_web_lab_timeline_tab(web_client):
    response = web_client.get("/lab/uc3?tab=timeline&seed=0")
    assert response.status_code == 200
    assert b"timeline" in response.data.lower()


def test_web_lab_dashboard_tab(web_client):
    response = web_client.get("/lab/uc3?tab=dashboard&seed=0")
    assert response.status_code == 200
    assert b"FIRED" in response.data or b"NOT" in response.data


def test_web_lab_overview_tab(web_client):
    response = web_client.get("/lab/uc3?tab=overview&seed=0")
    assert response.status_code == 200
    assert b"Infrastructure" in response.data


def test_web_unknown_lab_returns_404(web_client):
    response = web_client.get("/lab/nonexistent_xyz")
    assert response.status_code == 404


def test_web_lab_with_seed(web_client):
    r1 = web_client.get("/lab/uc3?seed=42")
    r2 = web_client.get("/lab/uc3?seed=42")
    assert r1.status_code == 200
    # Same seed → deterministic output, same content length
    assert len(r1.data) == len(r2.data)
