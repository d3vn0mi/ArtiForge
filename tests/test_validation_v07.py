"""Tests for v0.7 correlation-aware validation checks."""

import pytest
from click.testing import CliRunner
from artiforge.cli import main


@pytest.fixture
def runner():
    return CliRunner()


def test_validate_strict_passes_uc3(runner):
    result = runner.invoke(main, ["validate", "--lab", "uc3", "--strict"])
    assert result.exit_code == 0
    assert "OK" in result.output or "WARN" in result.output


def test_validate_strict_reports_strict_checks(runner):
    result = runner.invoke(main, ["validate", "--lab", "uc3", "--strict"])
    assert result.exit_code == 0
    assert "Strict checks" in result.output
