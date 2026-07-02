"""Tests for workspace rule hunting."""

import json

from traceforge import core
from traceforge.hunt import render_hunt_markdown, run_hunt, write_hunt


def _write_rules(path):
    path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom.left-marker",
                        "name": "Left marker",
                        "level": "medium",
                        "any": [{"contains": "left marker"}],
                        "description": "Marker used in the left sample.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def test_run_hunt_matches_stored_case_reports(tmp_path):
    cases_root = tmp_path / "cases"
    left = tmp_path / "left.bin"
    right = tmp_path / "right.bin"
    left.write_bytes(b"left marker http://left.example.com\n")
    right.write_bytes(b"right marker http://right.example.com\n")
    core.scan_file(left, cases_root=cases_root)
    core.scan_file(right, cases_root=cases_root)
    rules = tmp_path / "rules.json"
    _write_rules(rules)

    payload = run_hunt(cases_root, rules)

    assert payload["case_count"] == 2
    assert payload["rule_count"] == 1
    assert payload["match_count"] == 1
    assert payload["matched_case_count"] == 1
    assert payload["matches"][0]["rule_id"] == "custom.left-marker"
    assert payload["matches"][0]["file_name"] == "left.bin"


def test_write_hunt_creates_json_csv_and_markdown(tmp_path):
    cases_root = tmp_path / "cases"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hunt target VendorName\n")
    core.scan_file(sample, cases_root=cases_root)
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom.vendor",
                        "name": "Vendor marker",
                        "level": "info",
                        "any": [{"contains": "VendorName"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "hunt-out"

    paths = write_hunt(cases_root, rules, output)

    assert {path.name for path in paths} == {"hunt.json", "hunt.csv", "hunt.md"}
    assert "custom.vendor" in (output / "hunt.csv").read_text(encoding="utf-8")
    payload = json.loads((output / "hunt.json").read_text(encoding="utf-8"))
    assert payload["matches"][0]["rule_id"] == "custom.vendor"
    assert "Vendor marker" in (output / "hunt.md").read_text(encoding="utf-8")


def test_render_hunt_markdown_handles_no_matches():
    text = render_hunt_markdown(
        {
            "cases_root": "cases",
            "rules_path": "built-in",
            "rule_count": 1,
            "case_count": 0,
            "matched_case_count": 0,
            "match_count": 0,
            "error_count": 0,
            "matches": [],
            "errors": [],
        }
    )

    assert text.startswith("# Hunt results")
    assert "No rule matches." in text
