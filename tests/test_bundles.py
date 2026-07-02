"""Tests for portable case bundles."""

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from traceforge import cli, core


def _make_case(tmp_path: Path) -> Path:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"bundle marker http://bundle.example.test\n")
    return core.scan_file(sample, cases_root=tmp_path / "cases")


def test_case_bundle_round_trip(tmp_path):
    case_dir = _make_case(tmp_path)
    bundle = core.create_case_bundle(case_dir, tmp_path / "case.traceforge.zip")

    verification = core.verify_case_bundle(bundle)

    assert verification["valid"] is True
    assert verification["case_id"] == case_dir.name
    assert verification["verified_count"] == verification["file_count"]
    imported = core.import_case_bundle(bundle, tmp_path / "imported")
    imported_dir = Path(imported["case_dir"])
    assert imported_dir.name == case_dir.name
    assert (imported_dir / "report.json").read_bytes() == (case_dir / "report.json").read_bytes()


def test_case_bundle_requires_overwrite_for_existing_case(tmp_path):
    case_dir = _make_case(tmp_path)
    bundle = core.create_case_bundle(case_dir, tmp_path / "case.traceforge.zip")
    root = tmp_path / "imported"

    core.import_case_bundle(bundle, root)
    with pytest.raises(FileExistsError):
        core.import_case_bundle(bundle, root)

    result = core.import_case_bundle(bundle, root, overwrite=True)

    assert result["overwritten"] is True
    assert (Path(result["case_dir"]) / "manifest.json").is_file()


def test_case_bundle_verify_reports_hash_mismatch(tmp_path):
    bundle = tmp_path / "bad.traceforge.zip"
    content = b"changed report"
    manifest = {
        "kind": "traceforge.case-bundle",
        "schema_version": 1,
        "created_utc": "2026-07-03T00:00:00Z",
        "tool": "traceforge",
        "tool_version": "0.23.0",
        "case_id": "bad-case",
        "file_count": 1,
        "total_size": len(content),
        "files": [
            {
                "path": "report.json",
                "size": len(content),
                "sha256": "0" * 64,
            }
        ],
    }
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("bundle_manifest.json", json.dumps(manifest))
        archive.writestr("case/report.json", content)

    verification = core.verify_case_bundle(bundle)

    assert verification["valid"] is False
    assert "sha256 mismatch: report.json" in verification["errors"]
    with pytest.raises(ValueError):
        core.import_case_bundle(bundle, tmp_path / "cases")


def test_case_bundle_verify_rejects_unsafe_manifest_path(tmp_path):
    bundle = tmp_path / "unsafe.traceforge.zip"
    content = b"report"
    manifest = {
        "kind": "traceforge.case-bundle",
        "schema_version": 1,
        "created_utc": "2026-07-03T00:00:00Z",
        "tool": "traceforge",
        "tool_version": "0.23.0",
        "case_id": "unsafe-case",
        "file_count": 1,
        "total_size": len(content),
        "files": [
            {
                "path": "../report.json",
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        ],
    }
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("bundle_manifest.json", json.dumps(manifest))
        archive.writestr("case/../report.json", content)

    verification = core.verify_case_bundle(bundle)

    assert verification["valid"] is False
    assert any("unsafe" in error for error in verification["errors"])


def test_bundle_cli_commands(tmp_path, capsys):
    case_dir = _make_case(tmp_path)
    bundle = tmp_path / "cli.traceforge.zip"
    imported_root = tmp_path / "imported"

    assert cli.main(["bundle", "create", str(case_dir), "-o", str(bundle)]) == 0
    assert "wrote" in capsys.readouterr().out

    assert cli.main(["bundle", "verify", str(bundle)]) == 0
    assert "bundle valid" in capsys.readouterr().out

    assert (
        cli.main(
            [
                "bundle",
                "import",
                str(bundle),
                "--cases-root",
                str(imported_root),
            ]
        )
        == 0
    )
    assert (imported_root / case_dir.name / "report.json").is_file()
