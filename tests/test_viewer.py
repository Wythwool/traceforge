"""Tests for the self-contained case viewer."""

import json
import re

from traceforge import core
from traceforge.graph import build_graph
from traceforge.viewer import render_case_viewer, write_case_viewer


def _script_payload(text: str) -> dict:
    match = re.search(
        r'<script id="viewer-data" type="application/json">(.*?)</script>',
        text,
        re.DOTALL,
    )
    assert match is not None
    return json.loads(match.group(1))


def test_render_case_viewer_embeds_parseable_payload():
    payload = {
        "report": {
            "manifest": {
                "file_name": "sample.bin",
                "sha256": "abc123",
            },
            "score": {"score": 0},
            "extraction": {
                "format": {"kind": "raw"},
                "indicators": [],
                "code": {"xrefs": [], "functions": []},
            },
        },
        "graph": {
            "node_count": 1,
            "edge_count": 0,
            "nodes": [{"id": "sample", "type": "sample", "label": "sample.bin"}],
            "edges": [],
        },
    }

    html = render_case_viewer(payload)
    embedded = _script_payload(html)

    assert embedded["report"]["manifest"]["file_name"] == "sample.bin"
    assert embedded["graph"]["nodes"][0]["type"] == "sample"
    assert "Analyst Notes" in html
    assert "Code Xrefs" in html
    assert "function renderGraph" in html


def test_write_case_viewer_creates_static_html(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"viewer http://viewer.example.com\n")
    extraction = core.extract(sample.read_bytes(), sample.name)
    report = {
        "manifest": core.build_manifest(sample, extraction),
        "extraction": extraction,
        "score": {"score": 0, "max_score": 100, "label": "low", "reasons": []},
    }
    graph = build_graph(report)

    path = write_case_viewer(tmp_path / "case", report, graph)

    text = path.read_text(encoding="utf-8")
    payload = _script_payload(text)
    assert path.name == "viewer.html"
    assert payload["graph"]["node_count"] >= 1
    assert payload["report"]["extraction"]["indicators"]
    assert payload["annotations"]["status"] == "new"
