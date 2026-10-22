"""Unit tests for the unified modular Vector CLI."""

from __future__ import annotations

import typer
from typer.testing import CliRunner

from shared.vector_cli import app

runner = CliRunner()


def test_vector_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Velocitee Vector" in result.stdout
    assert "metal" in result.stdout
    assert "network" in result.stdout
    assert "services" in result.stdout
    assert "lifecycle" in result.stdout


def test_vector_status():
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "VELOCITEE VECTOR" in result.stdout
    assert "Vector Metal Engine" in result.stdout
    assert "Vector Network Engine" in result.stdout


def test_vector_services_profiles():
    result = runner.invoke(app, ["services", "profiles"])
    assert result.exit_code == 0
    assert "telia-nordic-core" in result.stdout
    assert "eu-finserv-strict" in result.stdout


def test_vector_services_deploy_dry():
    result = runner.invoke(app, ["services", "deploy", "--profile", "prism"])
    assert result.exit_code == 0
    assert "Velocitee Prism" in result.stdout


def test_vector_lifecycle_drift():
    result = runner.invoke(app, ["lifecycle", "drift"])
    assert result.exit_code == 0
    assert "Vector Lifecycle Engine" in result.stdout


def test_vector_run_unknown():
    result = runner.invoke(app, ["run", "invalid_module"])
    assert result.exit_code == 1
    assert "unknown module" in result.output
