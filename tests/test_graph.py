"""Tests for graph.json structure and determinism."""

import json

from traceforge import core
from traceforge.graph import EDGE_TYPES, NODE_TYPES, build_graph

SAMPLE = (
    b"graph marker string\n"
    b"http://graph.example.com/x\n"
    b"10.1.2.3\n"
)


def make_case(tmp_path):
    sample = tmp_path / "graph.bin"
    sample.write_bytes(SAMPLE)
    case_dir = core.scan_file(sample, cases_root=tmp_path / "cases")
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    graph = json.loads((case_dir / "graph.json").read_text(encoding="utf-8"))
    return report, graph


def test_graph_node_and_edge_types(tmp_path):
    _, graph = make_case(tmp_path)
    node_types = {node["type"] for node in graph["nodes"]}
    assert node_types == set(NODE_TYPES)
    edge_types = {edge["type"] for edge in graph["edges"]}
    assert edge_types == set(EDGE_TYPES)


def test_graph_edges_reference_existing_nodes(tmp_path):
    _, graph = make_case(tmp_path)
    node_ids = {node["id"] for node in graph["nodes"]}
    assert len(node_ids) == len(graph["nodes"])
    for edge in graph["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
    assert graph["node_count"] == len(graph["nodes"])
    assert graph["edge_count"] == len(graph["edges"])


def test_graph_links_indicator_to_string(tmp_path):
    _, graph = make_case(tmp_path)
    nodes = {node["id"]: node for node in graph["nodes"]}
    references = [edge for edge in graph["edges"] if edge["type"] == "references"]
    assert references
    for edge in references:
        source = nodes[edge["source"]]
        target = nodes[edge["target"]]
        assert source["type"] == "string"
        assert target["type"] == "indicator"
        assert target["value"].lower() in source["label"].lower()


def test_graph_is_deterministic(tmp_path):
    report, graph = make_case(tmp_path)
    assert build_graph(report) == graph
    assert build_graph(report) == build_graph(report)
