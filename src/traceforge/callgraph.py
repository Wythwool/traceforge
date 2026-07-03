"""Call graph summaries built from static code cross-references."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

MAX_CALLGRAPH_FUNCTIONS = 512
MAX_CALLGRAPH_IMPORTS = 512
MAX_CALLGRAPH_EXTERNALS = 256
MAX_CALLGRAPH_EDGES = 1024
MAX_EDGE_SITES = 16


def build_call_graph(extraction: dict, filename: str = "") -> dict:
    """Return a compact graph of function, import, and external references."""
    code = extraction.get("code", {})
    api_families = _api_families_by_import(extraction.get("apis", {}))
    nodes: dict[str, dict] = {}
    functions_by_name: dict[str, str] = {}
    functions_by_address: dict[int, str] = {}
    imports_by_name: dict[str, str] = {}
    external_count = 0

    for item in code.get("functions", [])[:MAX_CALLGRAPH_FUNCTIONS]:
        address = item.get("address")
        name = item.get("name") or (f"sub_{address:x}" if isinstance(address, int) else "function")
        node_id = _function_id(name, address)
        nodes[node_id] = {
            "id": node_id,
            "kind": "function",
            "name": name,
            "address": address,
            "offset": item.get("offset"),
            "source": item.get("source", ""),
            "calls_out": 0,
            "calls_in": 0,
        }
        functions_by_name.setdefault(name, node_id)
        if isinstance(address, int):
            functions_by_address[address] = node_id

    edges: dict[tuple[str, str, str, bool], dict] = {}
    for xref in code.get("xrefs", []):
        if len(edges) >= MAX_CALLGRAPH_EDGES:
            break
        source_name = xref.get("source_function", "")
        source_id = functions_by_name.get(source_name)
        if not source_id:
            source_id = _function_node_for_source(
                xref,
                nodes,
                functions_by_name,
                functions_by_address,
            )
        if not source_id:
            continue

        target_id, external_count = _target_node(
            xref,
            nodes,
            functions_by_name,
            functions_by_address,
            imports_by_name,
            api_families,
            external_count,
        )
        if not target_id:
            continue

        kind = xref.get("kind", "") or "reference"
        indirect = bool(xref.get("indirect"))
        key = (source_id, target_id, kind, indirect)
        edge = edges.get(key)
        if edge is None:
            source_node = nodes[source_id]
            target_node = nodes[target_id]
            edge = {
                "source": source_id,
                "source_kind": source_node.get("kind", ""),
                "source_name": source_node.get("name", ""),
                "source_address": source_node.get("address"),
                "target": target_id,
                "target_kind": target_node.get("kind", ""),
                "target_name": target_node.get("name", ""),
                "target_address": target_node.get("address"),
                "target_library": target_node.get("library", ""),
                "kind": kind,
                "indirect": indirect,
                "count": 0,
                "sites": [],
            }
            edges[key] = edge
        edge["count"] += 1
        if len(edge["sites"]) < MAX_EDGE_SITES:
            edge["sites"].append(
                {
                    "address": xref.get("source"),
                    "offset": xref.get("source_offset"),
                    "mnemonic": xref.get("mnemonic", ""),
                    "operands": xref.get("operands", ""),
                }
            )

    for edge in edges.values():
        source = nodes.get(edge["source"])
        target = nodes.get(edge["target"])
        if source is not None:
            source["calls_out"] = source.get("calls_out", 0) + edge["count"]
        if target is not None:
            target["calls_in"] = target.get("calls_in", 0) + edge["count"]

    node_rows = list(nodes.values())
    edge_rows = sorted(
        edges.values(),
        key=lambda item: (
            item.get("source_name", ""),
            item.get("target_kind", ""),
            item.get("target_name", ""),
            item.get("kind", ""),
        ),
    )
    function_rows = [item for item in node_rows if item.get("kind") == "function"]
    import_rows = [item for item in node_rows if item.get("kind") == "import"]
    external_rows = [item for item in node_rows if item.get("kind") == "external"]
    return {
        "engine": "traceforge-callgraph",
        "file_name": filename,
        "format": extraction.get("format", {}).get("kind", "raw"),
        "architecture": code.get("architecture", "unknown"),
        "node_count": len(node_rows),
        "edge_count": len(edge_rows),
        "function_count": len(function_rows),
        "import_count": len(import_rows),
        "external_count": len(external_rows),
        "internal_call_count": _edge_count(edge_rows, "function", "call"),
        "import_call_count": _edge_count(edge_rows, "import", "call"),
        "branch_count": sum(
            item.get("count", 0)
            for item in edge_rows
            if item.get("kind") == "branch"
        ),
        "functions": sorted(function_rows, key=_node_sort_key),
        "imports": sorted(import_rows, key=lambda item: item.get("name", "")),
        "externals": sorted(external_rows, key=lambda item: item.get("name", "")),
        "edges": edge_rows,
        "truncated": {
            "functions": len(code.get("functions", [])) > MAX_CALLGRAPH_FUNCTIONS,
            "edges": len(code.get("xrefs", [])) > MAX_CALLGRAPH_EDGES,
            "sites": any(len(item.get("sites", [])) >= MAX_EDGE_SITES for item in edge_rows),
        },
    }


def write_callgraph_csv(path: Path, payload: dict) -> Path:
    """Write call graph edges as a flat CSV table."""
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "source_kind",
                "source_name",
                "source_address",
                "target_kind",
                "target_name",
                "target_address",
                "target_library",
                "kind",
                "indirect",
                "count",
                "sites",
            ]
        )
        for edge in payload.get("edges", []):
            writer.writerow(
                [
                    edge.get("source_kind", ""),
                    edge.get("source_name", ""),
                    _hex_or_empty(edge.get("source_address")),
                    edge.get("target_kind", ""),
                    edge.get("target_name", ""),
                    _hex_or_empty(edge.get("target_address")),
                    edge.get("target_library", ""),
                    edge.get("kind", ""),
                    edge.get("indirect", False),
                    edge.get("count", 0),
                    ";".join(_hex_or_empty(site.get("address")) for site in edge.get("sites", [])),
                ]
            )
    return Path(path)


def write_callgraph_dot(path: Path, payload: dict) -> Path:
    """Write a Graphviz DOT view of call graph nodes and edges."""
    lines = [
        "digraph traceforge_callgraph {",
        "  graph [rankdir=LR];",
        '  node [fontname="Consolas", shape=box, style=rounded];',
    ]
    for node in payload.get("functions", []):
        label = node.get("name", "")
        address = _hex_or_empty(node.get("address"))
        if address:
            label = f"{label}\\n{address}"
        lines.append(f'  "{_dot_id(node.get("id", ""))}" [label="{_dot_escape(label)}"];')
    for node in payload.get("imports", []):
        lines.append(
            f'  "{_dot_id(node.get("id", ""))}" '
            f'[label="{_dot_escape(node.get("name", ""))}", shape=component];'
        )
    for node in payload.get("externals", []):
        lines.append(
            f'  "{_dot_id(node.get("id", ""))}" '
            f'[label="{_dot_escape(node.get("name", ""))}", shape=ellipse];'
        )
    for edge in payload.get("edges", []):
        label = edge.get("kind", "reference")
        if edge.get("count", 0) > 1:
            label = f"{label} x{edge['count']}"
        attrs = [f'label="{_dot_escape(label)}"']
        if edge.get("indirect"):
            attrs.append("style=dashed")
        lines.append(
            f'  "{_dot_id(edge.get("source", ""))}" -> '
            f'"{_dot_id(edge.get("target", ""))}" [{", ".join(attrs)}];'
        )
    lines.append("}")
    lines.append("")
    Path(path).write_text("\n".join(lines), encoding="utf-8")
    return Path(path)


def dumps(payload: dict) -> str:
    """Render stable JSON for CLI output."""
    return json.dumps(payload, indent=2) + "\n"


def _function_node_for_source(
    xref: dict,
    nodes: dict[str, dict],
    functions_by_name: dict[str, str],
    functions_by_address: dict[int, str],
) -> str | None:
    source = xref.get("source")
    if isinstance(source, int):
        node_id = functions_by_address.get(source)
        if node_id:
            return node_id
    name = xref.get("source_function") or (f"sub_{source:x}" if isinstance(source, int) else "")
    if not name:
        return None
    node_id = _function_id(name, source if isinstance(source, int) else None)
    nodes[node_id] = {
        "id": node_id,
        "kind": "function",
        "name": name,
        "address": source if isinstance(source, int) else None,
        "offset": xref.get("source_offset"),
        "source": "xref",
        "calls_out": 0,
        "calls_in": 0,
    }
    functions_by_name.setdefault(name, node_id)
    if isinstance(source, int):
        functions_by_address[source] = node_id
    return node_id


def _target_node(
    xref: dict,
    nodes: dict[str, dict],
    functions_by_name: dict[str, str],
    functions_by_address: dict[int, str],
    imports_by_name: dict[str, str],
    api_families: dict[tuple[str, str], list[str]],
    external_count: int,
) -> tuple[str | None, int]:
    target_kind = xref.get("target_kind", "") or "external"
    target_name = xref.get("target_name", "")
    target = xref.get("target")
    if target_kind == "function":
        node_id = functions_by_address.get(target) if isinstance(target, int) else None
        node_id = node_id or functions_by_name.get(target_name)
        if node_id:
            return node_id, external_count
        if isinstance(target, int):
            name = target_name or f"sub_{target:x}"
            node_id = _function_id(name, target)
            nodes[node_id] = {
                "id": node_id,
                "kind": "function",
                "name": name,
                "address": target,
                "offset": xref.get("target_offset"),
                "source": "xref_target",
                "calls_out": 0,
                "calls_in": 0,
            }
            functions_by_name.setdefault(name, node_id)
            functions_by_address[target] = node_id
            return node_id, external_count
    if target_kind == "import":
        display = target_name or xref.get("target_import", "") or "import"
        key = display.lower()
        node_id = imports_by_name.get(key)
        if node_id:
            return node_id, external_count
        library = xref.get("target_library", "")
        name = xref.get("target_import", "") or _split_import_name(display)[1]
        families = api_families.get((library.lower(), name.lower()), [])
        node_id = f"import:{_slug(display)}"
        nodes[node_id] = {
            "id": node_id,
            "kind": "import",
            "name": display,
            "library": library,
            "import": name,
            "address": target if isinstance(target, int) else None,
            "families": families,
            "calls_out": 0,
            "calls_in": 0,
        }
        imports_by_name[key] = node_id
        return node_id, external_count
    if external_count >= MAX_CALLGRAPH_EXTERNALS:
        return None, external_count
    name = target_name or (_hex_or_empty(target) if isinstance(target, int) else "external")
    node_id = f"external:{_slug(name)}"
    if node_id not in nodes:
        nodes[node_id] = {
            "id": node_id,
            "kind": "external",
            "name": name,
            "address": target if isinstance(target, int) else None,
            "calls_out": 0,
            "calls_in": 0,
        }
        external_count += 1
    return node_id, external_count


def _api_families_by_import(payload: dict) -> dict[tuple[str, str], list[str]]:
    values: dict[tuple[str, str], list[str]] = {}
    for item in payload.get("imports", []):
        library = str(item.get("library", "")).lower()
        name = str(item.get("name", "")).lower()
        if not name:
            continue
        families = [str(value) for value in item.get("families", []) if value]
        values[(library, name)] = families
    return values


def _split_import_name(display: str) -> tuple[str, str]:
    if "!" in display:
        library, name = display.split("!", 1)
        return library, name
    return "", display


def _edge_count(edges: list[dict], target_kind: str, kind: str) -> int:
    return sum(
        item.get("count", 0)
        for item in edges
        if item.get("target_kind") == target_kind and item.get("kind") == kind
    )


def _node_sort_key(item: dict) -> tuple[int, str]:
    address = item.get("address")
    return (address if isinstance(address, int) else 2**63 - 1, item.get("name", ""))


def _function_id(name: str, address: int | None) -> str:
    if isinstance(address, int):
        return f"function:{address:x}"
    return f"function:{_slug(name)}"


def _slug(value: object) -> str:
    text = str(value or "").lower()
    text = re.sub(r"[^a-z0-9_.:-]+", "_", text).strip("_")
    return text[:96] or "item"


def _dot_id(value: object) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"')


def _dot_escape(value: object) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _hex_or_empty(value: int | None) -> str:
    return "" if value is None else f"0x{value:x}"
