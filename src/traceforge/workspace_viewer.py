"""Self-contained workspace browser for indexed cases."""

from __future__ import annotations

import html
import json
from pathlib import Path

WORKSPACE_VIEWER_NAME = "workspace.html"
MAX_WORKSPACE_CASES = 2500

_STYLE = """
:root {
  --bg: #f6f7f8;
  --ink: #18222d;
  --muted: #5e6b78;
  --line: #d8e0e7;
  --panel: #ffffff;
  --soft: #edf2f5;
  --accent: #145c72;
  --high: #a3332d;
  --medium: #9b651e;
  --low: #2f765b;
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
  grid-template-columns: minmax(260px, 1fr) auto;
  gap: 16px;
  align-items: center;
  padding: 16px 18px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
}
h1 {
  margin: 0;
  font-size: 19px;
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
  min-width: 78px;
  padding: 7px 9px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--soft);
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
  grid-template-columns: minmax(520px, 1fr) 360px;
  min-height: calc(100vh - 82px);
}
.left, .detail {
  min-width: 0;
  padding: 12px;
  background: var(--panel);
}
.left {
  border-right: 1px solid var(--line);
}
.toolbar {
  display: grid;
  grid-template-columns: minmax(200px, 1fr) 160px 160px 160px;
  gap: 8px;
  margin-bottom: 12px;
}
input, select {
  min-height: 34px;
  width: 100%;
  padding: 6px 8px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fff;
  color: var(--ink);
  font: inherit;
}
table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
  font-size: 12px;
}
th, td {
  padding: 7px 8px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}
th {
  color: var(--muted);
  font-weight: 650;
  background: #f1f4f6;
}
tr {
  cursor: pointer;
}
tr.active {
  background: #e5f2f5;
}
a {
  color: var(--accent);
  text-decoration: none;
}
a:hover {
  text-decoration: underline;
}
.pill {
  display: inline-block;
  margin: 1px 3px 1px 0;
  padding: 2px 7px;
  border-radius: 999px;
  background: var(--soft);
  color: var(--muted);
  font-size: 11px;
}
.score-high { color: var(--high); font-weight: 650; }
.score-medium { color: var(--medium); font-weight: 650; }
.score-low { color: var(--low); font-weight: 650; }
.detail h2 {
  margin: 0 0 4px;
  font-size: 16px;
}
.detail h3 {
  margin: 18px 0 8px;
  font-size: 13px;
}
.kv {
  display: grid;
  grid-template-columns: 128px minmax(0, 1fr);
  gap: 6px 10px;
  margin-top: 10px;
}
.kv dt {
  color: var(--muted);
}
.kv dd {
  margin: 0;
  overflow-wrap: anywhere;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  font-size: 12px;
}
.links {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 12px;
}
.links a {
  padding: 5px 8px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fff;
}
.empty {
  padding: 18px 0;
  color: var(--muted);
}
@media (max-width: 980px) {
  header { grid-template-columns: 1fr; }
  .metrics { justify-content: stretch; }
  .metric { flex: 1 1 92px; }
  main { grid-template-columns: 1fr; }
  .left { border-right: 0; border-bottom: 1px solid var(--line); }
  .toolbar { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 620px) {
  .toolbar { grid-template-columns: 1fr; }
}
"""

_SCRIPT = """
const payload = JSON.parse(document.getElementById("workspace-data").textContent);
const cases = payload.cases || [];
const state = {
  q: "",
  status: "all",
  format: "all",
  tag: "all",
  selected: cases[0]?.case_id || ""
};
const byId = new Map(cases.map(row => [row.case_id, row]));
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
function fillSelect(id, values) {
  const node = document.getElementById(id);
  node.innerHTML = "";
  for (const value of ["all", ...values]) node.appendChild(el("option", { value }, value));
  node.onchange = event => {
    state[id.replace("-filter", "")] = event.target.value;
    renderWorkspace();
  };
}
function setupFilters() {
  fillSelect("status-filter", [...new Set(cases.map(row => row.status || "new"))].sort());
  fillSelect("format-filter", [...new Set(cases.map(row => row.format || "raw"))].sort());
  fillSelect("tag-filter", [...new Set(cases.flatMap(row => row.tags || []))].sort());
  document.getElementById("search").oninput = event => {
    state.q = event.target.value.trim().toLowerCase();
    renderWorkspace();
  };
}
function matches(row) {
  const hay = JSON.stringify(row).toLowerCase();
  return hay.includes(state.q)
    && (state.status === "all" || row.status === state.status)
    && (state.format === "all" || row.format === state.format)
    && (state.tag === "all" || (row.tags || []).includes(state.tag));
}
function scoreClass(score) {
  if (score >= 70) return "score-high";
  if (score >= 35) return "score-medium";
  return "score-low";
}
function caseLinks(row) {
  const wrap = el("div", { class: "links" });
  for (const link of row.links || []) {
    wrap.appendChild(el("a", { href: link.href }, link.label));
  }
  return wrap;
}
function renderTags(tags) {
  const wrap = el("div");
  for (const tag of tags || []) wrap.appendChild(el("span", { class: "pill" }, tag));
  if (!(tags || []).length) wrap.appendChild(el("span", { class: "pill" }, "none"));
  return wrap;
}
function renderWorkspace() {
  const body = document.getElementById("case-body");
  body.innerHTML = "";
  const rows = cases.filter(matches);
  document.getElementById("visible-count").textContent = rows.length;
  for (const row of rows) {
    const tr = el("tr");
    tr.classList.toggle("active", row.case_id === state.selected);
    tr.onclick = () => {
      state.selected = row.case_id;
      renderWorkspace();
      renderDetail();
    };
    const score = el("td", { class: scoreClass(row.score || 0) }, String(row.score || 0));
    const name = el("td");
    name.appendChild(
      el("a", { href: row.viewer_href || "#" }, short(row.file_name || row.case_id, 80))
    );
    name.appendChild(el("div", { class: "subline" }, short(row.case_id, 90)));
    const tags = el("td");
    tags.appendChild(renderTags(row.tags || []));
    tr.append(
      name,
      el("td", {}, row.format || "raw"),
      el("td", {}, row.status || "new"),
      tags,
      score,
      el("td", {}, String(row.indicator_count || 0)),
      el("td", {}, String(row.function_count || 0)),
      el("td", {}, String(row.xref_count || 0)),
      el("td", {}, String(row.note_count || 0))
    );
    body.appendChild(tr);
  }
  document.getElementById("empty").hidden = rows.length > 0;
}
function renderDetail() {
  const row = byId.get(state.selected) || cases[0];
  const detail = document.getElementById("detail");
  if (!row) {
    detail.innerHTML = '<div class="empty">No cases indexed.</div>';
    return;
  }
  detail.innerHTML = "";
  detail.appendChild(el("h2", {}, row.file_name || row.case_id));
  detail.appendChild(el("div", { class: "subline" }, row.case_id));
  detail.appendChild(caseLinks(row));
  const dl = el("dl", { class: "kv" });
  for (const [key, value] of [
    ["sha256", row.sha256],
    ["source", row.source_path],
    ["format", row.format],
    ["status", row.status],
    ["tags", (row.tags || []).join(", ") || "none"],
    ["score", row.score],
    ["size", row.size],
    ["created", row.created_utc],
    ["indicators", row.indicator_count],
    ["rules", row.rule_match_count],
    ["strings", row.string_count],
    ["imports", row.import_count],
    ["exports", row.export_count],
    ["functions", row.function_count],
    ["basic blocks", row.basic_block_count],
    ["xrefs", row.xref_count],
    ["notes", row.note_count],
    ["latest note", row.latest_note_text || row.latest_note_title || ""],
    ["note author", row.latest_note_author || ""],
    ["note time", row.latest_note_utc || ""]
  ]) {
    dl.append(el("dt", {}, key), el("dd", {}, String(value ?? "")));
  }
  detail.appendChild(dl);
}
setupFilters();
renderWorkspace();
renderDetail();
"""


def write_workspace_viewer(cases_root: Path, index: dict) -> Path:
    """Write workspace.html below a cases root."""
    root = Path(cases_root)
    root.mkdir(parents=True, exist_ok=True)
    target = root / WORKSPACE_VIEWER_NAME
    target.write_text(render_workspace_viewer(root, index), encoding="utf-8")
    return target


def render_workspace_viewer(cases_root: Path, index: dict) -> str:
    """Render a complete static workspace browser."""
    payload = _viewer_payload(cases_root, index)
    cases = payload.get("cases", [])
    high_score = max((case.get("score", 0) for case in cases), default=0)
    open_count = sum(1 for case in cases if case.get("status") not in {"benign", "done"})
    note_count = sum(int(case.get("note_count", 0)) for case in cases)
    data = _json_for_script(payload)
    return "\n".join(
        [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>TraceForge workspace</title>",
            f"<style>{_STYLE}</style>",
            "</head>",
            "<body>",
            "<header>",
            "<div>",
            "<h1>TraceForge workspace</h1>",
            f"<div class=\"subline\">{html.escape(str(cases_root))}</div>",
            "</div>",
            "<div class=\"metrics\">",
            _metric("cases", payload.get("case_count", 0)),
            _metric("visible", '<span id="visible-count">0</span>', raw=True),
            _metric("open", open_count),
            _metric("high score", high_score),
            _metric("notes", note_count),
            "</div>",
            "</header>",
            "<main>",
            '<section class="left">',
            '<div class="toolbar">',
            '<input id="search" type="search" placeholder="Search cases">',
            '<select id="status-filter" aria-label="Status filter"></select>',
            '<select id="format-filter" aria-label="Format filter"></select>',
            '<select id="tag-filter" aria-label="Tag filter"></select>',
            "</div>",
            "<table>",
            "<thead><tr>",
            "<th>Case</th><th>Format</th><th>Status</th><th>Tags</th>",
            "<th>Score</th><th>IOCs</th><th>Funcs</th><th>Xrefs</th><th>Notes</th>",
            "</tr></thead>",
            '<tbody id="case-body"></tbody>',
            "</table>",
            '<div id="empty" class="empty" hidden>No matching cases.</div>',
            "</section>",
            '<aside id="detail" class="detail"></aside>',
            "</main>",
            f'<script id="workspace-data" type="application/json">{data}</script>',
            f"<script>{_SCRIPT}</script>",
            "</body>",
            "</html>",
            "",
        ]
    )


def _viewer_payload(cases_root: Path, index: dict) -> dict:
    root = Path(cases_root)
    cases = [
        _case_for_viewer(root, row)
        for row in index.get("cases", [])[:MAX_WORKSPACE_CASES]
    ]
    return {
        "created_utc": index.get("created_utc", ""),
        "cases_root": str(root),
        "case_count": index.get("case_count", len(cases)),
        "error_count": index.get("error_count", 0),
        "cases": cases,
        "errors": index.get("errors", []),
        "truncated": len(index.get("cases", [])) > len(cases),
    }


def _case_for_viewer(cases_root: Path, row: dict) -> dict:
    case_dir = Path(row.get("case_dir", ""))
    viewer_href = _relative_href(cases_root, case_dir / "viewer.html")
    return {
        "case_id": row.get("case_id", ""),
        "file_name": row.get("file_name", ""),
        "source_path": row.get("source_path", ""),
        "sha256": row.get("sha256", ""),
        "size": row.get("size", 0),
        "created_utc": row.get("created_utc", ""),
        "format": row.get("format", "raw"),
        "format_confidence": row.get("format_confidence", ""),
        "score": row.get("score", 0),
        "label": row.get("label", ""),
        "status": row.get("status", "new"),
        "tags": row.get("tags", []),
        "note_count": row.get("note_count", 0),
        "latest_note_title": row.get("latest_note_title", ""),
        "latest_note_text": row.get("latest_note_text", ""),
        "latest_note_author": row.get("latest_note_author", ""),
        "latest_note_utc": row.get("latest_note_utc", ""),
        "annotations_updated_utc": row.get("annotations_updated_utc", ""),
        "indicator_count": row.get("indicator_count", 0),
        "rule_match_count": row.get("rule_match_count", 0),
        "string_count": row.get("string_count", 0),
        "section_count": row.get("section_count", 0),
        "resource_count": row.get("resource_count", 0),
        "debug_entry_count": row.get("debug_entry_count", 0),
        "import_count": row.get("import_count", 0),
        "export_count": row.get("export_count", 0),
        "symbol_count": row.get("symbol_count", 0),
        "function_count": row.get("function_count", 0),
        "basic_block_count": row.get("basic_block_count", 0),
        "xref_count": row.get("xref_count", 0),
        "code_edge_count": row.get("code_edge_count", 0),
        "embedded_artifact_count": row.get("embedded_artifact_count", 0),
        "viewer_href": viewer_href,
        "links": [
            {"label": "viewer", "href": viewer_href},
            {"label": "report", "href": _relative_href(cases_root, case_dir / "report.html")},
            {"label": "summary", "href": _relative_href(cases_root, case_dir / "summary.md")},
            {
                "label": "annotations",
                "href": _relative_href(cases_root, case_dir / "annotations.md"),
            },
        ],
    }


def _relative_href(root: Path, target: Path) -> str:
    try:
        value = target.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        value = target
    return Path(value).as_posix()


def _metric(label: str, value: object, *, raw: bool = False) -> str:
    strong = str(value) if raw else html.escape(str(value))
    return (
        '<div class="metric">'
        f"<strong>{strong}</strong>"
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
