"""Tests for the self-contained workspace browser."""

import json
import re

from traceforge import core
from traceforge.workspace_viewer import render_workspace_viewer, write_workspace_viewer


def _script_payload(text: str) -> dict:
    match = re.search(
        r'<script id="workspace-data" type="application/json">(.*?)</script>',
        text,
        re.DOTALL,
    )
    assert match is not None
    return json.loads(match.group(1))


def test_render_workspace_viewer_embeds_case_rows(tmp_path):
    index = {
        "created_utc": "2026-07-02T00:00:00Z",
        "case_count": 1,
        "error_count": 0,
        "cases": [
            {
                "case_id": "sample.bin-abc",
                "case_dir": str(tmp_path / "sample.bin-abc"),
                "file_name": "sample.bin",
                "sha256": "a" * 64,
                "format": "raw",
                "score": 12,
                "status": "triage",
                "tags": ["needs-review"],
                "note_count": 1,
                "latest_note_text": "Open in the case viewer first.",
                "indicator_count": 2,
                "function_count": 0,
                "xref_count": 0,
            }
        ],
        "errors": [],
    }

    html = render_workspace_viewer(tmp_path, index)
    payload = _script_payload(html)

    assert payload["case_count"] == 1
    assert payload["cases"][0]["status"] == "triage"
    assert payload["cases"][0]["latest_note_text"] == "Open in the case viewer first."
    assert payload["cases"][0]["viewer_href"].endswith("viewer.html")
    assert "TraceForge workspace" in html
    assert "function renderWorkspace" in html


def test_write_workspace_viewer_links_to_case_files(tmp_path):
    cases_root = tmp_path / "cases"
    one = tmp_path / "one.bin"
    two = tmp_path / "two.bin"
    one.write_bytes(b"one http://one.example.com 10.1.1.1\n")
    two.write_bytes(b"two http://two.example.com 10.2.2.2\n")
    first_case = core.scan_file(one, cases_root=cases_root)
    core.scan_file(two, cases_root=cases_root)
    core.annotate_case(
        first_case,
        status="triage",
        add_tags=("Needs Review",),
        note_text="Open in the case viewer first.",
    )

    index = core.build_cases_index(cases_root)
    path = write_workspace_viewer(cases_root, index)

    text = path.read_text(encoding="utf-8")
    payload = _script_payload(text)
    assert path.name == "workspace.html"
    assert payload["case_count"] == 2
    assert any(case["tags"] == ["needs-review"] for case in payload["cases"])
    assert any(
        "Open in the case viewer first." in case["latest_note_text"]
        for case in payload["cases"]
    )
    assert all(case["viewer_href"].endswith("viewer.html") for case in payload["cases"])
    assert "workspace-data" in text
