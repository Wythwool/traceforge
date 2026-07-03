"""Tests for case files, report rendering and indicator exports."""

import csv
import hashlib
import json

from traceforge import core

SAMPLE = (
    b"report marker string\n"
    b"http://example.com/item\n"
    b"192.168.10.20\n"
    b"HKLM\\Software\\Example\n"
)

CASE_FILES = {
    "manifest.json",
    "report.json",
    "report.html",
    "summary.md",
    "indicators.csv",
    "indicators.json",
    "graph.json",
}


def scan_sample(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(SAMPLE)
    return core.scan_file(sample, cases_root=tmp_path / "cases")


def test_case_files_created(tmp_path):
    case_dir = scan_sample(tmp_path)
    assert CASE_FILES <= {entry.name for entry in case_dir.iterdir()}


def test_report_json_content(tmp_path):
    case_dir = scan_sample(tmp_path)
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    assert set(report) == {"manifest", "extraction", "score"}
    assert report["manifest"]["file_name"] == "sample.bin"
    assert report["manifest"]["sha256"] == report["extraction"]["hashes"]["sha256"]
    assert "symbols" in report["extraction"]
    assert "code" in report["extraction"]
    assert 0 <= report["score"]["score"] <= report["score"]["max_score"]
    manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest == report["manifest"]


def test_indicator_exports_match(tmp_path):
    case_dir = scan_sample(tmp_path)
    with (case_dir / "indicators.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    assert rows[0] == ["type", "value", "source"]
    payload = json.loads((case_dir / "indicators.json").read_text(encoding="utf-8"))
    assert payload["count"] == len(rows) - 1
    assert payload["count"] == len(payload["indicators"])
    pairs = {(item["type"], item["value"]) for item in payload["indicators"]}
    assert ("url", "http://example.com/item") in pairs
    assert ("ipv4", "192.168.10.20") in pairs
    assert ("registry_path", "HKLM\\Software\\Example") in pairs


def test_html_and_summary_render(tmp_path):
    case_dir = scan_sample(tmp_path)
    html_text = (case_dir / "report.html").read_text(encoding="utf-8")
    assert html_text.startswith("<!DOCTYPE html>")
    assert "sample.bin" in html_text
    assert "Indicators" in html_text
    assert "Format Profile" in html_text
    assert "Symbols" in html_text
    assert "Code Map" in html_text
    assert "</html>" in html_text
    summary = (case_dir / "summary.md").read_text(encoding="utf-8")
    assert summary.startswith("# TraceForge summary: sample.bin")
    assert "Symbols:" in summary
    assert "Format profile:" in summary
    assert "Code:" in summary
    assert hashlib.sha256(SAMPLE).hexdigest() in summary


def test_regenerate_after_delete(tmp_path):
    case_dir = scan_sample(tmp_path)
    (case_dir / "report.html").unlink()
    (case_dir / "summary.md").unlink()
    (case_dir / "indicators.csv").unlink()
    (case_dir / "indicators.json").unlink()
    core.regenerate_reports(case_dir)
    core.regenerate_exports(case_dir)
    assert CASE_FILES <= {entry.name for entry in case_dir.iterdir()}


def test_empty_file_still_produces_reports(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    case_dir = core.scan_file(empty, cases_root=tmp_path / "cases")
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    assert report["extraction"]["size"] == 0
    assert report["extraction"]["chunks"]["total"] == 0
    assert report["score"]["score"] == 0
    assert CASE_FILES <= {entry.name for entry in case_dir.iterdir()}
