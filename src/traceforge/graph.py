"""Graph construction for TraceForge cases.

Node types: sample, format, section, import, export, symbol, chunk, string,
indicator, rule_match, embedded_artifact, finding.
Edge types: contains, references, has_indicator, has_finding, has_format,
has_rule, imports, exports, defines, embeds.
"""

# Caps keep graph.json readable for very large inputs.
MAX_GRAPH_STRINGS_PER_SOURCE = 200
MAX_GRAPH_CHUNKS = 256
MAX_GRAPH_IMPORTS = 256
MAX_GRAPH_EXPORTS = 256
MAX_GRAPH_SYMBOLS = 256
MAX_GRAPH_SECTIONS = 256
LABEL_MAX = 80

NODE_TYPES = (
    "sample",
    "format",
    "section",
    "import",
    "export",
    "symbol",
    "chunk",
    "string",
    "indicator",
    "rule_match",
    "embedded_artifact",
    "finding",
)
EDGE_TYPES = (
    "contains",
    "references",
    "has_indicator",
    "has_finding",
    "has_format",
    "has_rule",
    "imports",
    "exports",
    "defines",
    "embeds",
)


def _short(text: str, limit: int = LABEL_MAX) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def build_graph(report: dict) -> dict:
    """Build a deterministic node/edge graph from a report dict."""
    manifest = report["manifest"]
    extraction = report["extraction"]
    score = report["score"]

    nodes: list[dict] = []
    edges: list[dict] = []

    sample_id = "sample"
    nodes.append(
        {
            "id": sample_id,
            "type": "sample",
            "label": manifest["file_name"],
            "sha256": extraction["hashes"]["sha256"],
            "size": extraction["size"],
            "score": score["score"],
            "score_label": score["label"],
        }
    )

    format_info = extraction.get("format", {})
    format_id = "format"
    nodes.append(
        {
            "id": format_id,
            "type": "format",
            "label": format_info.get("kind", "raw"),
            "kind": format_info.get("kind", "raw"),
            "confidence": format_info.get("confidence", "low"),
            "extension": format_info.get("extension", ""),
        }
    )
    edges.append({"source": sample_id, "target": format_id, "type": "has_format"})
    _add_format_nodes(nodes, edges, sample_id, extraction)

    for record in extraction["chunks"]["records"][:MAX_GRAPH_CHUNKS]:
        node_id = f"chunk:{record['index']}"
        nodes.append(
            {
                "id": node_id,
                "type": "chunk",
                "label": f"chunk {record['index']} @ {record['offset']}",
                "offset": record["offset"],
                "size": record["size"],
                "entropy": record["entropy"],
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "contains"})

    string_nodes: list[tuple[str, str, str]] = []
    for source in ("ascii", "utf16le"):
        values = extraction["strings"][source]["values"][:MAX_GRAPH_STRINGS_PER_SOURCE]
        for index, value in enumerate(values):
            node_id = f"string:{source}:{index}"
            nodes.append(
                {
                    "id": node_id,
                    "type": "string",
                    "label": _short(value),
                    "source": source,
                    "length": len(value),
                }
            )
            edges.append({"source": sample_id, "target": node_id, "type": "contains"})
            string_nodes.append((node_id, source, value))

    for index, indicator in enumerate(extraction["indicators"]):
        node_id = f"indicator:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "indicator",
                "label": _short(f"{indicator['type']}: {indicator['value']}"),
                "indicator_type": indicator["type"],
                "value": indicator["value"],
                "string_source": indicator["source"],
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "has_indicator"})
        needle = indicator["value"].lower()
        for string_id, source, value in string_nodes:
            if source == indicator["source"] and needle in value.lower():
                edges.append({"source": string_id, "target": node_id, "type": "references"})
                break

    for index, match in enumerate(extraction.get("rules", {}).get("matches", [])):
        node_id = f"rule:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "rule_match",
                "label": _short(match["name"]),
                "rule_id": match["id"],
                "level": match["level"],
                "evidence": match["evidence"],
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "has_rule"})

    for reason in score["reasons"]:
        node_id = f"finding:{reason['signal']}"
        nodes.append(
            {
                "id": node_id,
                "type": "finding",
                "label": _short(reason["detail"]),
                "signal": reason["signal"],
                "points": reason["points"],
                "evidence": reason["evidence"],
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "has_finding"})

    return {
        "directed": True,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


def _add_format_nodes(
    nodes: list[dict],
    edges: list[dict],
    sample_id: str,
    extraction: dict,
) -> None:
    details = extraction.get("format", {}).get("details", {})
    sections = details.get("sections", []) or details.get("segments", [])
    for index, section in enumerate(sections[:MAX_GRAPH_SECTIONS]):
        node_id = f"section:{index}"
        label = section.get("name") or section.get("label") or f"section {index}"
        nodes.append(
            {
                "id": node_id,
                "type": "section",
                "label": _short(str(label)),
                "offset": section.get("raw_offset", section.get("offset", section.get("fileoff"))),
                "size": section.get("raw_size", section.get("size", section.get("filesize"))),
                "executable": section.get("executable"),
                "writable": section.get("writable"),
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "contains"})

    symbol_info = extraction.get("symbols", {})
    imports = _flatten_imports(details.get("imports", []))
    imports.extend(_flatten_imports(symbol_info.get("imports", [])))
    imports = _dedupe_values(imports)
    for index, item in enumerate(imports[:MAX_GRAPH_IMPORTS]):
        node_id = f"import:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "import",
                "label": _short(item),
                "name": item,
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "imports"})

    exports = _flatten_exports(details.get("exports", []))
    exports.extend(_flatten_exports(symbol_info.get("exports", [])))
    exports = _dedupe_values(exports)
    for index, item in enumerate(exports[:MAX_GRAPH_EXPORTS]):
        node_id = f"export:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "export",
                "label": _short(item),
                "name": item,
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "exports"})

    for index, item in enumerate(symbol_info.get("symbols", [])[:MAX_GRAPH_SYMBOLS]):
        name = item.get("name", "")
        if not name:
            continue
        node_id = f"symbol:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "symbol",
                "label": _short(name),
                "name": name,
                "kind": item.get("kind", item.get("type", "")),
                "binding": item.get("binding", ""),
                "section": item.get("section", item.get("section_index", "")),
                "undefined": item.get("undefined", ""),
                "value": item.get("value", ""),
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "defines"})

    for index, artifact in enumerate(extraction.get("format", {}).get("embedded", [])):
        node_id = f"embedded:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "embedded_artifact",
                "label": f"{artifact['kind']} @ {artifact['offset']}",
                "kind": artifact["kind"],
                "offset": artifact["offset"],
                "magic": artifact["magic"],
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "embeds"})


def _flatten_imports(imports: list) -> list[str]:
    values = []
    for item in imports:
        if isinstance(item, str):
            values.append(item)
        elif "library" in item:
            library = item.get("library", "")
            symbols = item.get("symbols", [])
            if not symbols:
                values.append(library)
            for symbol in symbols:
                name = symbol.get("name") or f"ordinal_{symbol.get('ordinal')}"
                values.append(f"{library}!{name}" if library else name)
        elif "module" in item:
            values.append(f"{item.get('module')}::{item.get('name')}")
        elif "name" in item:
            values.append(item["name"])
    return values


def _dedupe_values(values: list[str]) -> list[str]:
    seen = set()
    unique = []
    for value in values:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(value)
    return unique


def _flatten_exports(exports: list) -> list[str]:
    values = []
    for item in exports:
        if isinstance(item, str):
            values.append(item)
        elif "name" in item:
            values.append(item["name"])
    return values
