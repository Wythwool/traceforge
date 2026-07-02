"""Tests for case indexing and case comparison."""

import json

from traceforge import core
from traceforge.workspace import build_case_index, diff_cases, write_case_diff


def test_build_case_index_summarizes_cases(tmp_path):
    cases_root = tmp_path / "cases"
    one = tmp_path / "one.bin"
    two = tmp_path / "two.bin"
    one.write_bytes(b"alpha http://one.example.com 10.1.1.1\n")
    two.write_bytes(b"beta http://two.example.com 10.2.2.2\n")

    core.scan_file(one, cases_root=cases_root)
    core.scan_file(two, cases_root=cases_root)
    index = build_case_index(cases_root)

    assert index["case_count"] == 2
    assert index["error_count"] == 0
    assert {case["file_name"] for case in index["cases"]} == {"one.bin", "two.bin"}
    assert all(case["sha256"] for case in index["cases"])
    assert all(case["indicator_count"] >= 2 for case in index["cases"])


def test_diff_cases_reports_added_and_removed_values(tmp_path):
    cases_root = tmp_path / "cases"
    left = tmp_path / "left.bin"
    right = tmp_path / "right.bin"
    left.write_bytes(b"left http://left.example.com 10.1.1.1\n")
    right.write_bytes(b"right http://right.example.net 10.2.2.2\n" + b"MZ")

    left_case = core.scan_file(left, cases_root=cases_root)
    right_case = core.scan_file(right, cases_root=cases_root)
    diff = diff_cases(left_case, right_case)

    assert diff["same_sha256"] is False
    assert diff["indicators"]["added_count"] >= 2
    assert "url:http://right.example.net" in diff["indicators"]["added"]
    assert "url:http://left.example.com" in diff["indicators"]["removed"]
    assert diff["rule_matches"]["common_count"] >= 1


def test_write_case_diff_creates_json_and_markdown(tmp_path):
    cases_root = tmp_path / "cases"
    left = tmp_path / "left.bin"
    right = tmp_path / "right.bin"
    left.write_bytes(b"alpha text\n")
    right.write_bytes(b"alpha text with http://added.example.com\n")

    left_case = core.scan_file(left, cases_root=cases_root)
    right_case = core.scan_file(right, cases_root=cases_root)
    output = tmp_path / "diff"
    paths = write_case_diff(left_case, right_case, output)

    assert {path.name for path in paths} == {"diff.json", "diff.md"}
    payload = json.loads((output / "diff.json").read_text(encoding="utf-8"))
    assert payload["indicators"]["added_count"] >= 1
    assert (output / "diff.md").read_text(encoding="utf-8").startswith("# Case diff:")
