"""Tests for compact format profiles."""

import json

from test_formats import build_pe_with_metadata

from traceforge import cli, core


def test_pe_format_profile_highlights_metadata():
    extraction = core.extract(build_pe_with_metadata(), "sample.exe")
    profile = extraction["profile"]
    identifiers = {item["id"] for item in profile["observations"]}

    assert profile["engine"] == "traceforge-format-profile"
    assert profile["format"] == "pe"
    assert profile["summary"]["section_count"] == 1
    assert profile["summary"]["resource_count"] == 2
    assert profile["summary"]["debug_entry_count"] == 1
    assert profile["summary"]["certificate_count"] == 1
    assert profile["summary"]["fingerprint_count"] == 3
    assert profile["summary"]["rich_header_entry_count"] == 2
    assert profile["summary"]["version_info_count"] == 1
    assert profile["entry_point"]["section"] == ".text"
    assert "pe.tls-callbacks" in identifiers
    assert "pe.debug-records" in identifiers
    assert "pe.certificate-table" in identifiers
    assert "pe.delay-imphash" in identifiers
    assert "pe.rich-header" in identifiers
    assert "pe.version-info" in identifiers


def test_profile_cli_writes_json_and_csv(tmp_path, capsys):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe_with_metadata())
    csv_path = tmp_path / "profile.csv"

    assert cli.main(["profile", str(sample), "--csv", str(csv_path)]) == 0
    out = capsys.readouterr().out

    assert "pe" in out
    assert "wrote" in out
    assert "pe.tls-callbacks" in csv_path.read_text(encoding="utf-8")

    assert cli.main(["profile", str(sample), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["engine"] == "traceforge-format-profile"
    assert payload["summary"]["resource_count"] == 2


def test_scan_writes_format_profile_outputs(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe_with_metadata())

    case_dir = core.scan_file(sample, cases_root=tmp_path / "cases")
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))

    assert report["extraction"]["profile"]["format"] == "pe"
    assert (case_dir / "format_profile.csv").is_file()
    assert "pe.tls-callbacks" in (case_dir / "findings.csv").read_text(encoding="utf-8")
