"""Tests for call graph extraction and exports."""

import json

from test_code_map import build_pe_with_call, build_pe_with_import_call

from traceforge import cli, core
from traceforge.callgraph import build_call_graph, write_callgraph_csv, write_callgraph_dot


def test_callgraph_summarizes_internal_function_call():
    extraction = core.extract(build_pe_with_call(), "sample.exe")
    payload = build_call_graph(extraction, "sample.exe")

    assert payload["engine"] == "traceforge-callgraph"
    assert payload["function_count"] >= 2
    assert payload["edge_count"] == 1
    assert payload["internal_call_count"] == 1
    assert payload["edges"][0]["source_name"] == "entry"
    assert payload["edges"][0]["target_kind"] == "function"
    assert payload["edges"][0]["target_name"] == "sub_140001008"


def test_callgraph_resolves_indirect_import_call():
    extraction = core.extract(build_pe_with_import_call(), "imports.exe")
    payload = extraction["callgraph"]

    assert payload["import_call_count"] == 1
    assert payload["imports"][0]["name"] == "KERNEL32.dll!ExitProcess"
    assert payload["edges"][0]["indirect"] is True
    assert payload["edges"][0]["target_kind"] == "import"
    assert payload["edges"][0]["target_name"] == "KERNEL32.dll!ExitProcess"


def test_callgraph_exports_csv_and_dot(tmp_path):
    extraction = core.extract(build_pe_with_import_call(), "imports.exe")
    payload = extraction["callgraph"]
    csv_path = tmp_path / "callgraph.csv"
    dot_path = tmp_path / "callgraph.dot"

    write_callgraph_csv(csv_path, payload)
    write_callgraph_dot(dot_path, payload)

    assert "KERNEL32.dll!ExitProcess" in csv_path.read_text(encoding="utf-8")
    dot_text = dot_path.read_text(encoding="utf-8")
    assert "digraph traceforge_callgraph" in dot_text
    assert "ExitProcess" in dot_text


def test_callgraph_command_json_csv_and_dot(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    sample = tmp_path / "imports.exe"
    sample.write_bytes(build_pe_with_import_call())
    csv_path = tmp_path / "callgraph.csv"
    dot_path = tmp_path / "callgraph.dot"

    assert (
        cli.main(
            [
                "callgraph",
                str(sample),
                "--json",
                "--csv",
                str(csv_path),
                "--dot",
                str(dot_path),
            ]
        )
        == 0
    )

    out = capsys.readouterr().out
    payload = json.loads(out[out.index("{") :])
    assert payload["import_call_count"] == 1
    assert csv_path.is_file()
    assert dot_path.is_file()


def test_scan_embeds_callgraph_outputs(tmp_path):
    sample = tmp_path / "imports.exe"
    sample.write_bytes(build_pe_with_import_call())

    case_dir = core.scan_file(sample, cases_root=tmp_path / "cases")
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    graph = json.loads((case_dir / "graph.json").read_text(encoding="utf-8"))
    html = (case_dir / "report.html").read_text(encoding="utf-8")
    viewer = (case_dir / "viewer.html").read_text(encoding="utf-8")

    assert report["extraction"]["callgraph"]["import_call_count"] == 1
    assert "KERNEL32.dll!ExitProcess" in (case_dir / "callgraph.csv").read_text(
        encoding="utf-8"
    )
    assert "KERNEL32.dll!ExitProcess" in (case_dir / "callgraph.dot").read_text(
        encoding="utf-8"
    )
    assert "Call Graph" in html
    assert "Call graph:" in (case_dir / "summary.md").read_text(encoding="utf-8")
    assert "callgraph-table" in viewer
    node_by_id = {node["id"]: node for node in graph["nodes"]}
    assert any(
        edge["type"] == "calls"
        and node_by_id.get(edge["target"], {}).get("type") == "import"
        for edge in graph["edges"]
    )
