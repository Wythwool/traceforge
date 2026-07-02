"""Graph construction for TraceForge cases.

Node types: sample, chunk, string, indicator, finding.
Edge types: contains, references, has_indicator, has_finding.
"""

# Caps keep graph.json readable for very large inputs.
MAX_GRAPH_STRINGS_PER_SOURCE = 200
MAX_GRAPH_CHUNKS = 256
LABEL_MAX = 80

NODE_TYPES = ("sample", "chunk", "string", "indicator", "finding")
EDGE_TYPES = ("contains", "references", "has_indicator", "has_finding")


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
