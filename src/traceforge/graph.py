"""Graph construction for TraceForge cases.

Node types: sample, format, section, import, export, symbol, resource,
debug_info, tls_callback, certificate, code_range, function, basic_block,
code_xref, chunk, string, indicator, rule_match, embedded_artifact, finding.
Edge types: contains, references, has_indicator, has_finding, has_format,
has_rule, imports, exports, defines, calls, branches, embeds.
"""

# Caps keep graph.json readable for very large inputs.
MAX_GRAPH_STRINGS_PER_SOURCE = 200
MAX_GRAPH_CHUNKS = 256
MAX_GRAPH_IMPORTS = 256
MAX_GRAPH_EXPORTS = 256
MAX_GRAPH_SYMBOLS = 256
MAX_GRAPH_FUNCTIONS = 256
MAX_GRAPH_BASIC_BLOCKS = 512
MAX_GRAPH_XREFS = 512
MAX_GRAPH_CODE_RANGES = 128
MAX_GRAPH_SECTIONS = 256
MAX_GRAPH_RESOURCES = 256
MAX_GRAPH_DEBUG = 64
LABEL_MAX = 80

NODE_TYPES = (
    "sample",
    "format",
    "section",
    "import",
    "export",
    "symbol",
    "resource",
    "debug_info",
    "tls_callback",
    "certificate",
    "code_range",
    "function",
    "basic_block",
    "code_xref",
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
    "calls",
    "branches",
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
    _add_code_nodes(nodes, edges, sample_id, extraction)

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

    for index, item in enumerate(extraction.get("profile", {}).get("observations", [])):
        node_id = f"profile_finding:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "finding",
                "label": _short(item.get("detail", item.get("title", ""))),
                "source": "profile",
                "signal": item.get("id", ""),
                "level": item.get("level", ""),
                "evidence": [item.get("evidence", "")],
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "has_finding"})

    for index, item in enumerate(extraction.get("apis", {}).get("families", [])):
        node_id = f"api_family:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "finding",
                "label": _short(f"API: {item.get('name', item.get('id', ''))}"),
                "source": "api",
                "signal": item.get("id", ""),
                "level": item.get("confidence", ""),
                "evidence": [
                    f"{evidence.get('library', '')}:{evidence.get('name', '')}"
                    for evidence in item.get("evidence", [])[:16]
                ],
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

    for index, item in enumerate(details.get("resources", [])[:MAX_GRAPH_RESOURCES]):
        node_id = f"resource:{index}"
        label = f"{item.get('type', 'resource')} {item.get('name', '')}".strip()
        nodes.append(
            {
                "id": node_id,
                "type": "resource",
                "label": _short(label),
                "resource_type": item.get("type", ""),
                "name": item.get("name", ""),
                "language": item.get("language", ""),
                "offset": item.get("offset"),
                "size": item.get("size", 0),
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "contains"})

    for index, item in enumerate(details.get("debug", [])[:MAX_GRAPH_DEBUG]):
        codeview = item.get("codeview", {})
        node_id = f"debug:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "debug_info",
                "label": _short(codeview.get("pdb_path", item.get("type", "debug"))),
                "debug_type": item.get("type", ""),
                "pdb_path": codeview.get("pdb_path", ""),
                "offset": item.get("offset"),
                "size": item.get("size", 0),
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "contains"})

    for index, item in enumerate(details.get("tls", {}).get("callbacks", [])[:MAX_GRAPH_DEBUG]):
        node_id = f"tls_callback:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "tls_callback",
                "label": f"TLS callback 0x{item.get('address', 0):x}",
                "address": item.get("address"),
                "rva": item.get("rva"),
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "contains"})

    for index, item in enumerate(details.get("certificates", [])[:MAX_GRAPH_DEBUG]):
        node_id = f"certificate:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "certificate",
                "label": _short(item.get("type", "certificate")),
                "certificate_type": item.get("type", ""),
                "offset": item.get("offset"),
                "size": item.get("size", 0),
                "sha256": item.get("sha256", ""),
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "contains"})


def _add_code_nodes(
    nodes: list[dict],
    edges: list[dict],
    sample_id: str,
    extraction: dict,
) -> None:
    code = extraction.get("code", {})
    ranges = code.get("ranges", [])
    for index, item in enumerate(ranges[:MAX_GRAPH_CODE_RANGES]):
        node_id = f"code_range:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "code_range",
                "label": _short(item.get("name", f"code range {index}")),
                "name": item.get("name", ""),
                "offset": item.get("offset", 0),
                "size": item.get("size", 0),
                "virtual_address": item.get("virtual_address", 0),
                "permissions": item.get("permissions", ""),
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "contains"})

    functions = code.get("functions", [])
    function_nodes = {}
    function_nodes_by_name = {}
    for index, item in enumerate(functions[:MAX_GRAPH_FUNCTIONS]):
        address = item.get("address")
        if not isinstance(address, int):
            continue
        node_id = f"function:{index}"
        function_nodes[address] = node_id
        if item.get("name"):
            function_nodes_by_name[item["name"]] = node_id
        nodes.append(
            {
                "id": node_id,
                "type": "function",
                "label": _short(item.get("name", f"sub_{address:x}")),
                "name": item.get("name", ""),
                "address": address,
                "offset": item.get("offset"),
                "source": item.get("source", ""),
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "contains"})

    block_nodes = {}
    for index, item in enumerate(code.get("basic_blocks", [])[:MAX_GRAPH_BASIC_BLOCKS]):
        address = item.get("address")
        if not isinstance(address, int):
            continue
        node_id = f"basic_block:{index}"
        block_nodes[address] = node_id
        nodes.append(
            {
                "id": node_id,
                "type": "basic_block",
                "label": f"block 0x{address:x}",
                "address": address,
                "offset": item.get("offset"),
                "size": item.get("size", 0),
                "instruction_count": item.get("instruction_count", 0),
                "terminator": item.get("terminator", ""),
                "range": item.get("range", ""),
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "contains"})

    for source_address, source_id in block_nodes.items():
        block = next(
            (
                item
                for item in code.get("basic_blocks", [])
                if item.get("address") == source_address
            ),
            {},
        )
        for target in block.get("outgoing", []):
            target_id = block_nodes.get(target)
            if target_id:
                edges.append({"source": source_id, "target": target_id, "type": "branches"})

    for index, item in enumerate(code.get("xrefs", [])[:MAX_GRAPH_XREFS]):
        source = item.get("source")
        target = item.get("target")
        if not isinstance(source, int) or not isinstance(target, int):
            continue
        node_id = f"code_xref:{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "code_xref",
                "label": _short(f"{item.get('kind', 'xref')} 0x{source:x} -> 0x{target:x}"),
                "kind": item.get("kind", ""),
                "indirect": item.get("indirect", False),
                "source": source,
                "source_function": item.get("source_function", ""),
                "target": target,
                "target_kind": item.get("target_kind", ""),
                "target_name": item.get("target_name", ""),
                "target_library": item.get("target_library", ""),
                "target_import": item.get("target_import", ""),
                "target_range": item.get("target_range", ""),
            }
        )
        edges.append({"source": sample_id, "target": node_id, "type": "references"})

    function_starts = sorted(function_nodes)
    for item in code.get("edges", []):
        target = item.get("target")
        source = item.get("source")
        if not isinstance(target, int) or not isinstance(source, int):
            continue
        source_id = _function_node_for_address(source, function_starts, function_nodes)
        target_id = function_nodes.get(target)
        if source_id and target_id:
            edges.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "type": "calls" if item.get("kind") == "call" else "branches",
                }
            )

    import_nodes_by_name = {
        node.get("name", "").lower(): node.get("id")
        for node in nodes
        if node.get("type") == "import" and node.get("name")
    }
    for item in extraction.get("callgraph", {}).get("edges", [])[:MAX_GRAPH_XREFS]:
        if item.get("target_kind") != "import":
            continue
        source_id = function_nodes_by_name.get(item.get("source_name", ""))
        target_id = import_nodes_by_name.get(str(item.get("target_name", "")).lower())
        if source_id and target_id:
            edges.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "type": "calls",
                    "indirect": item.get("indirect", False),
                    "count": item.get("count", 0),
                }
            )


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


def _function_node_for_address(
    address: int,
    starts: list[int],
    nodes_by_address: dict[int, str],
) -> str | None:
    owner = None
    for start in starts:
        if start > address:
            break
        owner = start
    return nodes_by_address.get(owner) if owner is not None else None


def _flatten_exports(exports: list) -> list[str]:
    values = []
    for item in exports:
        if isinstance(item, str):
            values.append(item)
        elif "name" in item:
            values.append(item["name"])
    return values
