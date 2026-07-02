"""Tests for case annotations."""

import json

from traceforge import core
from traceforge.annotations import load_annotations, render_annotations_markdown


def test_scan_creates_annotation_files(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"annotation sample http://note.example.com\n")

    case_dir = core.scan_file(sample, cases_root=tmp_path / "cases")

    assert (case_dir / "annotations.json").is_file()
    assert (case_dir / "annotations.md").is_file()
    payload = load_annotations(case_dir)
    assert payload["status"] == "new"
    assert payload["case_id"] == case_dir.name
    assert payload["notes"] == []


def test_annotate_case_updates_tags_note_and_viewer(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"annotate me 10.4.3.2\n")
    case_dir = core.scan_file(sample, cases_root=tmp_path / "cases")

    paths = core.annotate_case(
        case_dir,
        status="in_progress",
        add_tags=("Packed Sample", "needs_symbols"),
        note_text="Check imports and strings before closing the case.",
        title="Triage",
        author="Analyst",
    )

    assert {path.name for path in paths} == {
        "annotations.json",
        "annotations.md",
        "viewer.html",
    }
    payload = json.loads((case_dir / "annotations.json").read_text(encoding="utf-8"))
    assert payload["status"] == "in_progress"
    assert payload["tags"] == ["needs_symbols", "packed-sample"]
    assert payload["notes"][0]["title"] == "Triage"
    assert payload["notes"][0]["author"] == "Analyst"
    viewer = (case_dir / "viewer.html").read_text(encoding="utf-8")
    assert "Analyst Notes" in viewer
    assert "packed-sample" in viewer
    assert "Check imports and strings" in viewer


def test_render_annotations_markdown_lists_notes():
    text = render_annotations_markdown(
        {
            "case_id": "case-one",
            "file_name": "sample.bin",
            "status": "triage",
            "tags": ["packed"],
            "updated_utc": "2026-07-02T00:00:00Z",
            "notes": [
                {
                    "id": "note-1",
                    "created_utc": "2026-07-02T00:00:00Z",
                    "author": "Analyst",
                    "title": "Finding",
                    "text": "Review the unpacking stub.",
                    "tags": ["packed"],
                }
            ],
        }
    )

    assert text.startswith("# Case annotations: case-one")
    assert "Status: `triage`" in text
    assert "Review the unpacking stub." in text
