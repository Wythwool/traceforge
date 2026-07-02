"""Tests for package metadata and repository checks."""

import tomllib
from pathlib import Path

import traceforge

ROOT = Path(__file__).resolve().parents[1]


def test_project_version_matches_package_version():
    payload = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert payload["project"]["version"] == traceforge.__version__
    assert payload["project"]["scripts"]["traceforge"] == "traceforge.cli:main"


def test_ci_workflow_runs_core_quality_gates():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "python -m ruff check ." in workflow
    assert "python -m pytest -q" in workflow
    assert "python -m build" in workflow
    assert "traceforge db build" in workflow
