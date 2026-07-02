"""Self-contained case viewer for TraceForge reports."""

from __future__ import annotations

import html
import json
from pathlib import Path

from traceforge.annotations import load_annotations
from traceforge.graph import build_graph

MAX_VIEWER_NODES = 900
MAX_VIEWER_EDGES = 1600
MAX_VIEWER_ROWS = 400

_STYLE = """
:root {
  --bg: #f7f8fa;
  --ink: #17202a;
  --muted: #5f6b77;
  --line: #d9e0e7;
  --panel: #ffffff;
  --panel-soft: #eef3f6;
  --accent: #145c72;
  --accent-soft: #d8eef3;
  --warn: #9b5b16;
  --high: #9f2d28;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--ink);
  font: 14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif;
}
header {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 16px;
  align-items: center;
  padding: 14px 18px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
}
h1 {
  margin: 0;
  font-size: 18px;
  font-weight: 650;
  letter-spacing: 0;
}
.subline {
  margin-top: 3px;
  color: var(--muted);
  font-size: 12px;
  word-break: break-all;
}
.metrics {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
}
.metric {
  min-width: 76px;
  padding: 7px 9px;
  background: var(--panel-soft);
  border: 1px solid var(--line);
  border-radius: 6px;
}
.metric strong {
  display: block;
  font-size: 15px;
}
.metric span {
  color: var(--muted);
  font-size: 11px;
}
main {
  display: grid;
  grid-template-columns: 280px minmax(460px, 1fr) 360px;
  gap: 0;
  min-height: calc(100vh - 78px);
}
aside, section {
  min-width: 0;
  border-right: 1px solid var(--line);
  background: var(--panel);
}
aside, .detail {
  padding: 12px;
  overflow: auto;
}
.toolbar {
  display: grid;
  gap: 8px;
  margin-bottom: 12px;
}
input, select, button {
  min-height: 34px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fff;
  color: var(--ink);
  font: inherit;
}
input, select { width: 100%; padding: 6px 8px; }
button { padding: 6px 10px; cursor: pointer; }
button.active {
  border-color: var(--accent);
  background: var(--accent-soft);
}
.tabs {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 6px;
}
.node-list {
  display: grid;
  gap: 5px;
}
.node-row {
  display: grid;
  grid-template-columns: 12px 1fr;
  gap: 8px;
  align-items: center;
  padding: 7px 8px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fff;
  cursor: pointer;
}
.node-row.active {
  border-color: var(--accent);
  background: var(--accent-soft);
}
.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--accent);
}
.node-row b {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.node-row span {
  color: var(--muted);
  font-size: 11px;
}
.graph-wrap {
  position: relative;
  background: #fbfcfd;
  min-width: 0;
}
#graph {
  width: 100%;
  height: calc(100vh - 78px);
  display: block;
}
.edge {
  stroke: #b9c5cf;
  stroke-width: 1.1;
  opacity: 0.62;
}
.edge.active {
  stroke: var(--accent);
  stroke-width: 2;
  opacity: 1;
}
.node {
  stroke: #ffffff;
  stroke-width: 1.5;
  cursor: pointer;
}
.node.active {
  stroke: #111820;
  stroke-width: 3;
}
.node-label {
  pointer-events: none;
  font-size: 10px;
  fill: #26323d;
}
.detail {
  border-right: 0;
}
.detail h2 {
  margin: 0 0 8px;
  font-size: 15px;
}
.detail h3 {
  margin: 16px 0 8px;
  font-size: 13px;
}
.kv {
  display: grid;
  grid-template-columns: 116px minmax(0, 1fr);
  gap: 6px 10px;
  padding: 8px 0;
  border-bottom: 1px solid var(--line);
}
.kv dt { color: var(--muted); }
.kv dd {
  margin: 0;
  overflow-wrap: anywhere;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 12px;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
th, td {
  padding: 6px 7px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}
th {
  color: var(--muted);
  font-weight: 600;
  background: #f3f6f8;
}
.pill {
  display: inline-block;
  padding: 2px 7px;
  border-radius: 999px;
  background: var(--panel-soft);
  color: var(--muted);
  font-size: 11px;
}
.empty {
  color: var(--muted);
  padding: 12px 0;
}
@media (max-width: 1120px) {
  main { grid-template-columns: 250px minmax(360px, 1fr); }
  .detail { grid-column: 1 / -1; border-top: 1px solid var(--line); }
}
@media (max-width: 760px) {
  header { grid-template-columns: 1fr; }
  .metrics { justify-content: stretch; }
  .metric { flex: 1 1 90px; }
  main { grid-template-columns: 1fr; }
  #graph { height: 480px; }
  aside, section { border-right: 0; border-bottom: 1px solid var(--line); }
}
"""

_SCRIPT = """
const payload = JSON.parse(document.getElementById("viewer-data").textContent);
const report = payload.report;
const graph = payload.graph;
const annotations = payload.annotations || {};
const nodes = graph.nodes || [];
const edges = graph.edges || [];
const colors = {
  sample: "#145c72",
  format: "#57606f",
  section: "#2f7d5a",
  import: "#8a5a13",
  export: "#7b4fa1",
  symbol: "#3c6ca8",
  resource: "#687f2d",
  debug_info: "#7d5f2a",
  tls_callback: "#9b5b16",
  certificate: "#596b7d",
  code_range: "#274c77",
  function: "#b14534",
  basic_block: "#cf7d1b",
  code_xref: "#5f4b8b",
  chunk: "#66747f",
  string: "#25836b",
  indicator: "#9f2d28",
  rule_match: "#8b3f7d",
  embedded_artifact: "#6c6f24",
  finding: "#b3261e"
};
const state = { q: "", type: "all", tab: "nodes", selected: nodes[0]?.id || "" };
const nodeById = new Map(nodes.map(node => [node.id, node]));
const adjacency = new Map();
for (const edge of edges) {
  if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
  if (!adjacency.has(edge.target)) adjacency.set(edge.target, []);
  adjacency.get(edge.source).push(edge);
  adjacency.get(edge.target).push(edge);
}
function el(name, attrs = {}, text = "") {
  const item = document.createElement(name);
  for (const [key, value] of Object.entries(attrs)) item.setAttribute(key, value);
  if (text) item.textContent = text;
  return item;
}
function short(text, limit = 72) {
  const value = String(text ?? "");
  return value.length > limit ? `${value.slice(0, limit - 1)}...` : value;
}
function matchNode(node) {
  const hay = JSON.stringify(node).toLowerCase();
  return (state.type === "all" || node.type === state.type) && hay.includes(state.q);
}
function nodeColor(type) {
  return colors[type] || "#66747f";
}
function selectNode(id) {
  state.selected = id;
  renderNodeList();
  renderGraph();
  renderDetail();
}
function renderTabs() {
  document.querySelectorAll("[data-tab]").forEach(button => {
    button.classList.toggle("active", button.dataset.tab === state.tab);
    button.onclick = () => {
      state.tab = button.dataset.tab;
      renderNodeList();
    };
  });
}
function renderFilters() {
  const types = ["all", ...new Set(nodes.map(node => node.type).sort())];
  const typeSelect = document.getElementById("type-filter");
  typeSelect.innerHTML = "";
  for (const type of types) typeSelect.appendChild(el("option", { value: type }, type));
  typeSelect.value = state.type;
  typeSelect.onchange = event => {
    state.type = event.target.value;
    renderNodeList();
    renderGraph();
  };
  const search = document.getElementById("search");
  search.oninput = event => {
    state.q = event.target.value.trim().toLowerCase();
    renderNodeList();
    renderGraph();
  };
}
function renderNodeList() {
  const list = document.getElementById("node-list");
  list.innerHTML = "";
  const rows = nodes.filter(matchNode).slice(0, 260);
  for (const node of rows) {
    const row = el("button", { class: "node-row", type: "button" });
    row.classList.toggle("active", node.id === state.selected);
    row.onclick = () => selectNode(node.id);
    const dot = el("i", { class: "dot" });
    dot.style.background = nodeColor(node.type);
    const text = el("span");
    text.appendChild(el("b", {}, short(node.label || node.id, 64)));
    text.appendChild(el("span", {}, `${node.type} · ${node.id}`));
    row.append(dot, text);
    list.appendChild(row);
  }
  if (!rows.length) list.appendChild(el("div", { class: "empty" }, "No matching nodes."));
}
function layoutNodes(width, height) {
  const groups = new Map();
  for (const node of nodes) {
    if (!matchNode(node) && node.id !== state.selected) continue;
    if (!groups.has(node.type)) groups.set(node.type, []);
    groups.get(node.type).push(node);
  }
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.max(120, Math.min(width, height) * 0.38);
  const placed = new Map();
  const groupEntries = [...groups.entries()];
  groupEntries.forEach(([type, group], groupIndex) => {
    const angle = (Math.PI * 2 * groupIndex) / Math.max(groupEntries.length, 1);
    const groupX = centerX + Math.cos(angle) * radius * 0.62;
    const groupY = centerY + Math.sin(angle) * radius * 0.62;
    const local = Math.max(36, 12 + group.length * 2);
    group.slice(0, 90).forEach((node, index) => {
      const localAngle = (Math.PI * 2 * index) / Math.max(group.length, 1);
      placed.set(node.id, {
        x: groupX + Math.cos(localAngle) * local,
        y: groupY + Math.sin(localAngle) * local,
        type
      });
    });
  });
  return placed;
}
function svgEl(name, attrs = {}) {
  const item = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attrs)) item.setAttribute(key, value);
  return item;
}
function renderGraph() {
  const svg = document.getElementById("graph");
  svg.innerHTML = "";
  const width = Math.max(svg.clientWidth, 520);
  const height = Math.max(svg.clientHeight, 420);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  const placed = layoutNodes(width, height);
  const activeEdges = new Set((adjacency.get(state.selected) || []).map(edge => edge));
  for (const edge of edges.slice(0, 1600)) {
    const a = placed.get(edge.source);
    const b = placed.get(edge.target);
    if (!a || !b) continue;
    const line = svgEl("line", {
      x1: a.x,
      y1: a.y,
      x2: b.x,
      y2: b.y,
      class: `edge ${activeEdges.has(edge) ? "active" : ""}`
    });
    svg.appendChild(line);
  }
  for (const node of nodes) {
    const point = placed.get(node.id);
    if (!point) continue;
    const group = svgEl("g");
    group.addEventListener("click", () => selectNode(node.id));
    const circle = svgEl("circle", {
      cx: point.x,
      cy: point.y,
      r: node.id === state.selected ? 8 : 6,
      fill: nodeColor(node.type),
      class: `node ${node.id === state.selected ? "active" : ""}`
    });
    const label = svgEl("text", {
      x: point.x + 9,
      y: point.y + 4,
      class: "node-label"
    });
    label.textContent = short(node.label || node.id, 28);
    group.append(circle, label);
    svg.appendChild(group);
  }
}
function renderObjectTable(target, object) {
  target.innerHTML = "";
  const dl = el("dl", { class: "kv" });
  for (const [key, value] of Object.entries(object || {})) {
    if (typeof value === "object" && value !== null) continue;
    dl.append(el("dt", {}, key), el("dd", {}, String(value)));
  }
  target.appendChild(dl);
}
function renderRows(target, headers, rows) {
  target.innerHTML = "";
  if (!rows.length) {
    target.appendChild(el("div", { class: "empty" }, "No rows."));
    return;
  }
  const table = el("table");
  const thead = el("thead");
  const tr = el("tr");
  for (const header of headers) tr.appendChild(el("th", {}, header));
  thead.appendChild(tr);
  const tbody = el("tbody");
  for (const row of rows.slice(0, 120)) {
    const bodyRow = el("tr");
    for (const header of headers) bodyRow.appendChild(el("td", {}, short(row[header], 120)));
    tbody.appendChild(bodyRow);
  }
  table.append(thead, tbody);
  target.appendChild(table);
}
function renderDetail() {
  const node = nodeById.get(state.selected) || nodes[0] || {};
  document.getElementById("detail-title").textContent = node.label || node.id || "Selection";
  document.getElementById("detail-kind").textContent = node.type || "none";
  renderObjectTable(document.getElementById("detail-fields"), node);
  const related = adjacency.get(node.id) || [];
  renderRows(
    document.getElementById("detail-edges"),
    ["type", "source", "target"],
    related.map(edge => ({
      type: edge.type,
      source: edge.source,
      target: edge.target
    }))
  );
  const code = report.extraction?.code || {};
  renderRows(
    document.getElementById("xref-table"),
    ["kind", "source_function", "target_kind", "target_name"],
    (code.xrefs || []).map(row => ({
      kind: row.indirect ? `${row.kind} indirect` : row.kind,
      source_function: row.source_function || "",
      target_kind: row.target_kind || "",
      target_name: row.target_name || ""
    }))
  );
}
function renderAnnotations() {
  const notes = annotations.notes || [];
  const tags = (annotations.tags || []).join(", ") || "none";
  renderRows(
    document.getElementById("annotation-table"),
    ["field", "value"],
    [
      { field: "status", value: annotations.status || "new" },
      { field: "tags", value: tags },
      { field: "notes", value: notes.length },
      { field: "updated", value: annotations.updated_utc || "" }
    ]
  );
  renderRows(
    document.getElementById("note-table"),
    ["title", "author", "text"],
    notes.map(note => ({
      title: note.title || note.id || "",
      author: note.author || "",
      text: note.text || ""
    }))
  );
}
function renderSummaryTables() {
  const extraction = report.extraction || {};
  renderRows(
    document.getElementById("indicator-table"),
    ["type", "value", "source"],
    (extraction.indicators || []).slice(0, 160)
  );
  renderRows(
    document.getElementById("function-table"),
    ["name", "address", "source"],
    (extraction.code?.functions || []).slice(0, 160).map(row => ({
      name: row.name,
      address: row.address ? `0x${row.address.toString(16)}` : "",
      source: row.source
    }))
  );
}
window.addEventListener("resize", renderGraph);
renderTabs();
renderFilters();
renderNodeList();
renderGraph();
renderDetail();
renderAnnotations();
renderSummaryTables();
"""


def write_case_viewer(
    case_dir: Path,
    report: dict,
    graph: dict | None = None,
    annotations: dict | None = None,
) -> Path:
    """Write a self-contained HTML viewer for a stored case."""
    target = Path(case_dir) / "viewer.html"
    target.parent.mkdir(parents=True, exist_ok=True)
    graph = graph if graph is not None else build_graph(report)
    payload = {
        "report": _viewer_report(report),
        "graph": _viewer_graph(graph),
        "annotations": _viewer_annotations(
            annotations if annotations is not None else load_annotations(target.parent)
        ),
    }
    target.write_text(render_case_viewer(payload), encoding="utf-8")
    return target


def render_case_viewer(payload: dict) -> str:
    """Render the complete viewer document."""
    report = payload.get("report", {})
    manifest = report.get("manifest", {})
    extraction = report.get("extraction", {})
    score = report.get("score", {})
    title = f"TraceForge viewer: {manifest.get('file_name', 'case')}"
    data = _json_for_script(payload)
    return "\n".join(
        [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{html.escape(title)}</title>",
            f"<style>{_STYLE}</style>",
            "</head>",
            "<body>",
            "<header>",
            "<div>",
            f"<h1>{html.escape(manifest.get('file_name', 'case'))}</h1>",
            f"<div class=\"subline\">{html.escape(manifest.get('sha256', ''))}</div>",
            "</div>",
            "<div class=\"metrics\">",
            _metric("format", extraction.get("format", {}).get("kind", "raw")),
            _metric("score", score.get("score", 0)),
            _metric("nodes", payload.get("graph", {}).get("node_count", 0)),
            _metric("edges", payload.get("graph", {}).get("edge_count", 0)),
            "</div>",
            "</header>",
            "<main>",
            "<aside>",
            "<div class=\"toolbar\">",
            '<input id="search" type="search" placeholder="Search">',
            '<select id="type-filter" aria-label="Node type"></select>',
            "<div class=\"tabs\">",
            '<button type="button" data-tab="nodes" class="active">Nodes</button>',
            '<button type="button" data-tab="graph">Graph</button>',
            '<button type="button" data-tab="case">Case</button>',
            "</div>",
            "</div>",
            '<div id="node-list" class="node-list"></div>',
            "</aside>",
            '<section class="graph-wrap"><svg id="graph" role="img"></svg></section>',
            '<section class="detail">',
            '<h2 id="detail-title">Selection</h2>',
            '<span id="detail-kind" class="pill">node</span>',
            '<div id="detail-fields"></div>',
            "<h3>Analyst Notes</h3>",
            '<div id="annotation-table"></div>',
            '<div id="note-table"></div>',
            "<h3>Related Edges</h3>",
            '<div id="detail-edges"></div>',
            "<h3>Code Xrefs</h3>",
            '<div id="xref-table"></div>',
            "<h3>Functions</h3>",
            '<div id="function-table"></div>',
            "<h3>Indicators</h3>",
            '<div id="indicator-table"></div>',
            "</section>",
            "</main>",
            f'<script id="viewer-data" type="application/json">{data}</script>',
            f"<script>{_SCRIPT}</script>",
            "</body>",
            "</html>",
            "",
        ]
    )


def _viewer_report(report: dict) -> dict:
    extraction = report.get("extraction", {})
    copied = {
        "manifest": report.get("manifest", {}),
        "score": report.get("score", {}),
        "extraction": {
            "size": extraction.get("size", 0),
            "hashes": extraction.get("hashes", {}),
            "format": extraction.get("format", {}),
            "indicators": extraction.get("indicators", [])[:MAX_VIEWER_ROWS],
            "rules": extraction.get("rules", {}),
            "symbols": _cap_symbol_rows(extraction.get("symbols", {})),
            "code": _cap_code_rows(extraction.get("code", {})),
            "strings": _cap_strings(extraction.get("strings", {})),
        },
    }
    return copied


def _viewer_graph(graph: dict) -> dict:
    nodes = graph.get("nodes", [])[:MAX_VIEWER_NODES]
    node_ids = {node.get("id") for node in nodes}
    edges = [
        edge
        for edge in graph.get("edges", [])
        if edge.get("source") in node_ids and edge.get("target") in node_ids
    ][:MAX_VIEWER_EDGES]
    return {
        "directed": graph.get("directed", True),
        "node_count": graph.get("node_count", len(graph.get("nodes", []))),
        "edge_count": graph.get("edge_count", len(graph.get("edges", []))),
        "nodes": nodes,
        "edges": edges,
        "truncated": {
            "nodes": len(graph.get("nodes", [])) > len(nodes),
            "edges": len(graph.get("edges", [])) > len(edges),
        },
    }


def _viewer_annotations(payload: dict) -> dict:
    return {
        "status": payload.get("status", "new"),
        "tags": payload.get("tags", []),
        "updated_utc": payload.get("updated_utc", ""),
        "notes": [
            {
                "id": note.get("id", ""),
                "created_utc": note.get("created_utc", ""),
                "author": note.get("author", ""),
                "title": note.get("title", ""),
                "text": note.get("text", ""),
                "tags": note.get("tags", []),
            }
            for note in payload.get("notes", [])[:MAX_VIEWER_ROWS]
        ],
    }


def _cap_symbol_rows(symbols: dict) -> dict:
    return {
        "imports": symbols.get("imports", [])[:MAX_VIEWER_ROWS],
        "exports": symbols.get("exports", [])[:MAX_VIEWER_ROWS],
        "symbols": symbols.get("symbols", [])[:MAX_VIEWER_ROWS],
        "relocations": symbols.get("relocations", [])[:MAX_VIEWER_ROWS],
        "needed_libraries": symbols.get("needed_libraries", []),
    }


def _cap_code_rows(code: dict) -> dict:
    return {
        "architecture": code.get("architecture", "unknown"),
        "decoder": code.get("decoder", {}),
        "entry_point": code.get("entry_point", {}),
        "ranges": code.get("ranges", [])[:MAX_VIEWER_ROWS],
        "functions": code.get("functions", [])[:MAX_VIEWER_ROWS],
        "basic_blocks": code.get("basic_blocks", [])[:MAX_VIEWER_ROWS],
        "xrefs": code.get("xrefs", [])[:MAX_VIEWER_ROWS],
        "instructions": code.get("instructions", [])[:MAX_VIEWER_ROWS],
        "edges": code.get("edges", [])[:MAX_VIEWER_ROWS],
    }


def _cap_strings(strings: dict) -> dict:
    capped = {"min_length": strings.get("min_length", 4)}
    for source in ("ascii", "utf16le"):
        values = strings.get(source, {})
        capped[source] = {
            "total": values.get("total", 0),
            "values": values.get("values", [])[:MAX_VIEWER_ROWS],
        }
    return capped


def _metric(label: str, value: object) -> str:
    return (
        '<div class="metric">'
        f"<strong>{html.escape(str(value))}</strong>"
        f"<span>{html.escape(label)}</span>"
        "</div>"
    )


def _json_for_script(payload: dict) -> str:
    text = json.dumps(payload, separators=(",", ":"))
    return (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
