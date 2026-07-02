"""Report rendering and indicator exports for TraceForge cases."""

import csv
import html
import json
from collections import Counter
from pathlib import Path

# Display caps for report.html; full data always lives in report.json.
MAX_HTML_INDICATOR_ROWS = 500
MAX_HTML_CHUNK_ROWS = 64
MAX_HTML_STRINGS = 50

_STYLE = """
body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem;
       padding: 0 1rem; color: #1c2733; }
h1 { border-bottom: 2px solid #1c2733; padding-bottom: 0.3rem; }
h2 { margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; }
th, td { border: 1px solid #b8c4cf; padding: 0.3rem 0.5rem; text-align: left;
         font-size: 0.9rem; vertical-align: top; word-break: break-all; }
th { background: #eef2f5; }
code, pre { font-family: ui-monospace, monospace; background: #f4f6f8; }
pre { padding: 0.5rem; overflow-x: auto; }
.badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 0.3rem;
         color: #fff; font-weight: 600; }
.badge.low { background: #2e7d32; }
.badge.medium { background: #b26a00; }
.badge.high { background: #b3261e; }
.note { color: #5a6772; font-size: 0.85rem; }
"""


def _write_text(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _write_json(path: Path, payload: dict) -> Path:
    return _write_text(path, json.dumps(payload, indent=2) + "\n")


def _table(headers: tuple, rows: list) -> str:
    head = "".join(f"<th>{html.escape(str(header))}</th>" for header in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_report_html(report: dict) -> str:
    manifest = report["manifest"]
    extraction = report["extraction"]
    score = report["score"]
    indicators = extraction["indicators"]
    chunks = extraction["chunks"]
    strings = extraction["strings"]
    format_info = extraction.get("format", {})
    rules = extraction.get("rules", {})
    window = extraction["entropy"]["byte_window"]
    label = score["label"]
    title = f"TraceForge report: {manifest['file_name']}"
    first_bytes = html.escape(extraction["first_bytes_hex"]) or "(empty file)"

    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>{html.escape(title)}</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        f"<h1>{html.escape(title)}</h1>",
        "<h2>File</h2>",
        _table(
            ("field", "value"),
            [
                ("file name", manifest["file_name"]),
                ("source path", manifest["source_path"]),
                ("case id", manifest["case_id"]),
                ("size", f"{extraction['size']} bytes"),
                ("created (UTC)", manifest["created_utc"]),
                ("tool", f"{manifest['tool']} {manifest['tool_version']}"),
            ],
        ),
        "<h2>Hashes</h2>",
        _table(("algorithm", "digest"), sorted(extraction["hashes"].items())),
        f"<p>First bytes (hex): <code>{first_bytes}</code></p>",
        "<h2>Format</h2>",
        _format_html(format_info),
        _symbols_html(extraction.get("symbols", {})),
        _code_html(extraction.get("code", {})),
        "<h2>Score</h2>",
        f'<p><span class="badge {label}">{label}</span> '
        f"{score['score']} / {score['max_score']}</p>",
    ]

    if score["reasons"]:
        parts.append(
            _table(
                ("signal", "points", "detail", "evidence"),
                [
                    (
                        reason["signal"],
                        reason["points"],
                        reason["detail"],
                        "; ".join(reason["evidence"]),
                    )
                    for reason in score["reasons"]
                ],
            )
        )
    else:
        parts.append('<p class="note">No scoring signals fired.</p>')

    parts.append(f"<h2>Indicators ({len(indicators)})</h2>")
    if indicators:
        shown = indicators[:MAX_HTML_INDICATOR_ROWS]
        parts.append(
            _table(
                ("type", "value", "source"),
                [(item["type"], item["value"], item["source"]) for item in shown],
            )
        )
        if len(indicators) > len(shown):
            parts.append(
                f'<p class="note">Showing first {len(shown)} of {len(indicators)} '
                "indicators; see indicators.csv for the full list.</p>"
            )
    else:
        parts.append('<p class="note">No indicators found.</p>')

    parts.append(f"<h2>Rule matches ({rules.get('match_count', 0)})</h2>")
    if rules.get("matches"):
        parts.append(
            _table(
                ("id", "level", "name", "evidence"),
                [
                    (
                        match["id"],
                        match["level"],
                        match["name"],
                        "; ".join(match["evidence"]),
                    )
                    for match in rules["matches"]
                ],
            )
        )
    else:
        parts.append('<p class="note">No local rules matched.</p>')

    parts.append("<h2>Entropy</h2>")
    parts.append(
        _table(
            ("measure", "value"),
            [
                ("overall", extraction["entropy"]["overall"]),
                ("byte window size", window["window_size"]),
                ("window count", window["count"]),
                ("window min", window["min"]),
                ("window max", window["max"]),
                ("window mean", window["mean"]),
            ],
        )
    )

    total_chunks = chunks["total"]
    parts.append(f"<h2>Chunks ({total_chunks} x {chunks['chunk_size']} bytes)</h2>")
    if chunks["records"]:
        shown_chunks = chunks["records"][:MAX_HTML_CHUNK_ROWS]
        parts.append(
            _table(
                ("index", "offset", "size", "entropy"),
                [
                    (record["index"], record["offset"], record["size"], record["entropy"])
                    for record in shown_chunks
                ],
            )
        )
        if total_chunks > len(shown_chunks):
            parts.append(
                f'<p class="note">Showing first {len(shown_chunks)} of {total_chunks} '
                "chunks; see report.json for the full list.</p>"
            )
    else:
        parts.append('<p class="note">Empty file: no chunks.</p>')

    parts.append("<h2>Strings</h2>")
    for source in ("ascii", "utf16le"):
        info = strings[source]
        parts.append(
            f"<h3>{source}: {info['total']} total "
            f"(min length {strings['min_length']})</h3>"
        )
        if info["values"]:
            sample = info["values"][:MAX_HTML_STRINGS]
            parts.append(
                f"<details><summary>First {len(sample)} strings</summary>"
                f"<pre>{html.escape(chr(10).join(sample))}</pre></details>"
            )
        else:
            parts.append('<p class="note">None found.</p>')

    parts.extend(["</body>", "</html>", ""])
    return "\n".join(parts)


def render_summary_md(report: dict) -> str:
    manifest = report["manifest"]
    extraction = report["extraction"]
    score = report["score"]
    counts = Counter(item["type"] for item in extraction["indicators"])
    format_info = extraction.get("format", {})
    rules = extraction.get("rules", {})

    lines = [
        f"# TraceForge summary: {manifest['file_name']}",
        "",
        f"- Case: `{manifest['case_id']}`",
        f"- Source: `{manifest['source_path']}`",
        f"- Size: {extraction['size']} bytes",
        f"- SHA-256: `{extraction['hashes']['sha256']}`",
        f"- Format: {format_info.get('kind', 'raw')}",
        (
            f"- Symbols: {len(extraction.get('symbols', {}).get('symbols', []))} total, "
            f"{len(extraction.get('symbols', {}).get('imports', []))} imports, "
            f"{len(extraction.get('symbols', {}).get('exports', []))} exports"
        ),
        (
            f"- Code: {len(extraction.get('code', {}).get('ranges', []))} ranges, "
            f"{len(extraction.get('code', {}).get('functions', []))} functions, "
            f"{len(extraction.get('code', {}).get('edges', []))} edges"
        ),
        f"- Score: {score['score']}/{score['max_score']} ({score['label']})",
        "",
        "## Indicator counts",
    ]
    if counts:
        lines.extend(f"- {kind}: {counts[kind]}" for kind in sorted(counts))
    else:
        lines.append("- none")

    lines.extend(["", "## Findings"])
    if score["reasons"]:
        lines.extend(
            f"- {reason['signal']} (+{reason['points']}): {reason['detail']}"
            for reason in score["reasons"]
        )
    else:
        lines.append("- none")

    lines.extend(["", "## Rule matches"])
    if rules.get("matches"):
        lines.extend(
            f"- {match['id']} ({match['level']}): {match['name']}"
            for match in rules["matches"]
        )
    else:
        lines.append("- none")

    strings = extraction["strings"]
    lines.extend(
        [
            "",
            (
                f"Strings: {strings['ascii']['total']} ASCII, "
                f"{strings['utf16le']['total']} UTF-16LE "
                f"(min length {strings['min_length']}). "
                f"Chunks: {extraction['chunks']['total']} x "
                f"{extraction['chunks']['chunk_size']} bytes. "
                f"Overall entropy: {extraction['entropy']['overall']}."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def _format_html(format_info: dict) -> str:
    details = format_info.get("details", {})
    parts = [
        _table(
            ("field", "value"),
            [
                ("kind", format_info.get("kind", "raw")),
                ("confidence", format_info.get("confidence", "low")),
                ("extension", format_info.get("extension", "")),
                ("error", format_info.get("error", "")),
            ],
        )
    ]

    sections = details.get("sections") or details.get("segments") or []
    if sections:
        parts.append("<h3>Sections / segments</h3>")
        parts.append(
            _table(
                ("name", "offset", "size", "flags"),
                [
                    (
                        section.get("name", ""),
                        section.get(
                            "raw_offset",
                            section.get("offset", section.get("fileoff", "")),
                        ),
                        section.get("raw_size", section.get("size", section.get("filesize", ""))),
                        section.get("characteristics", section.get("flags", "")),
                    )
                    for section in sections[:64]
                ],
            )
        )

    imports = _format_import_rows(details.get("imports", []))
    if imports:
        parts.append("<h3>Imports</h3>")
        parts.append(_table(("name",), [(item,) for item in imports[:128]]))

    exports = _format_export_rows(details.get("exports", []))
    if exports:
        parts.append("<h3>Exports</h3>")
        parts.append(_table(("name",), [(item,) for item in exports[:128]]))

    parts.append(_pe_resources_html(details.get("resources", [])))
    parts.append(_pe_debug_html(details))

    entries = details.get("entries", [])
    if entries:
        parts.append("<h3>Container entries</h3>")
        parts.append(
            _table(
                ("name", "size", "compressed", "crc32"),
                [
                    (
                        entry.get("name"),
                        entry.get("size"),
                        entry.get("compressed_size"),
                        entry.get("crc32"),
                    )
                    for entry in entries[:128]
                ],
            )
        )

    embedded = format_info.get("embedded", [])
    if embedded:
        parts.append("<h3>Embedded artifacts</h3>")
        parts.append(
            _table(
                ("kind", "offset", "magic"),
                [(item["kind"], item["offset"], item["magic"]) for item in embedded],
            )
        )
    return "\n".join(parts)


def _pe_resources_html(resources: list[dict]) -> str:
    if not resources:
        return ""
    rows = [
        (
            item.get("type", ""),
            item.get("name", ""),
            item.get("language", ""),
            item.get("offset", ""),
            item.get("size", ""),
            item.get("preview", ""),
        )
        for item in resources[:128]
    ]
    return "<h3>Resources</h3>\n" + _table(
        ("type", "name", "language", "offset", "size", "preview"), rows
    )


def _pe_debug_html(details: dict) -> str:
    rows = []
    for item in details.get("debug", []):
        codeview = item.get("codeview", {})
        rows.append(
            (
                "debug",
                item.get("type", ""),
                item.get("offset", ""),
                item.get("size", ""),
                codeview.get("pdb_path", codeview.get("format", "")),
            )
        )
    for item in details.get("tls", {}).get("callbacks", []):
        rows.append(
            (
                "tls callback",
                "",
                _hex_or_empty(item.get("rva")),
                "",
                _hex_or_empty(item.get("address")),
            )
        )
    for item in details.get("certificates", []):
        rows.append(
            (
                "certificate",
                item.get("type", ""),
                item.get("offset", ""),
                item.get("size", ""),
                item.get("sha256", ""),
            )
        )
    if not rows:
        return ""
    return "<h3>Debug, TLS and certificates</h3>\n" + _table(
        ("source", "type", "offset", "size", "detail"), rows
    )


def _symbols_html(symbol_info: dict) -> str:
    if not symbol_info:
        return ""
    parts = ["<h2>Symbols</h2>"]
    parts.append(
        _table(
            ("field", "value"),
            [
                ("imports", len(symbol_info.get("imports", []))),
                ("exports", len(symbol_info.get("exports", []))),
                ("symbols", len(symbol_info.get("symbols", []))),
                ("needed libraries", ", ".join(symbol_info.get("needed_libraries", []))),
                ("relocation blocks", len(symbol_info.get("relocations", []))),
            ],
        )
    )
    rows = []
    for source in ("imports", "exports", "symbols"):
        for item in symbol_info.get(source, [])[:128]:
            name = item.get("name", "")
            if name:
                rows.append((source, name, item.get("kind", ""), item.get("binding", "")))
    if rows:
        parts.append(_table(("source", "name", "kind", "binding"), rows))
    return "\n".join(parts)


def _code_html(code_info: dict) -> str:
    if not code_info:
        return ""
    parts = ["<h2>Code Map</h2>"]
    entry = code_info.get("entry_point", {})
    decoder = code_info.get("decoder", {})
    parts.append(
        _table(
            ("field", "value"),
            [
                ("architecture", code_info.get("architecture", "unknown")),
                ("decoder", decoder.get("engine", "")),
                ("ranges", len(code_info.get("ranges", []))),
                ("functions", len(code_info.get("functions", []))),
                ("basic blocks", len(code_info.get("basic_blocks", []))),
                ("xrefs", len(code_info.get("xrefs", []))),
                ("instructions", len(code_info.get("instructions", []))),
                ("edges", len(code_info.get("edges", []))),
                ("entry address", _hex_or_empty(entry.get("address"))),
                ("entry offset", _hex_or_empty(entry.get("offset"))),
            ],
        )
    )
    ranges = code_info.get("ranges", [])
    if ranges:
        parts.append("<h3>Executable ranges</h3>")
        parts.append(
            _table(
                ("name", "kind", "offset", "size", "address", "permissions"),
                [
                    (
                        item.get("name", ""),
                        item.get("kind", ""),
                        _hex_or_empty(item.get("offset")),
                        item.get("size", ""),
                        _hex_or_empty(item.get("virtual_address")),
                        item.get("permissions", ""),
                    )
                    for item in ranges[:64]
                ],
            )
        )
    functions = code_info.get("functions", [])
    if functions:
        parts.append("<h3>Function candidates</h3>")
        parts.append(
            _table(
                ("name", "address", "offset", "source"),
                [
                    (
                        item.get("name", ""),
                        _hex_or_empty(item.get("address")),
                        _hex_or_empty(item.get("offset")),
                        item.get("source", ""),
                    )
                    for item in functions[:128]
                ],
            )
        )
    blocks = code_info.get("basic_blocks", [])
    if blocks:
        parts.append("<h3>Basic blocks</h3>")
        parts.append(
            _table(
                ("address", "offset", "size", "instructions", "terminator", "outgoing"),
                [
                    (
                        _hex_or_empty(item.get("address")),
                        _hex_or_empty(item.get("offset")),
                        item.get("size", ""),
                        item.get("instruction_count", ""),
                        item.get("terminator", ""),
                        ", ".join(_hex_or_empty(value) for value in item.get("outgoing", [])),
                    )
                    for item in blocks[:128]
                ],
            )
        )
    xrefs = code_info.get("xrefs", [])
    if xrefs:
        parts.append("<h3>Code xrefs</h3>")
        parts.append(
            _table(
                (
                    "kind",
                    "indirect",
                    "source",
                    "source function",
                    "target",
                    "target kind",
                    "target name",
                ),
                [
                    (
                        item.get("kind", ""),
                        item.get("indirect", ""),
                        _hex_or_empty(item.get("source")),
                        item.get("source_function", ""),
                        _hex_or_empty(item.get("target")),
                        item.get("target_kind", ""),
                        item.get("target_name", ""),
                    )
                    for item in xrefs[:128]
                ],
            )
        )
    instructions = code_info.get("instructions", [])
    if instructions:
        parts.append("<h3>Instruction preview</h3>")
        parts.append(
            _table(
                ("address", "bytes", "mnemonic", "operands"),
                [
                    (
                        _hex_or_empty(item.get("address")),
                        item.get("bytes", ""),
                        item.get("mnemonic", ""),
                        item.get("operands", ""),
                    )
                    for item in instructions[:128]
                ],
            )
        )
    return "\n".join(parts)


def _format_import_rows(imports: list) -> list[str]:
    rows = []
    for item in imports:
        if isinstance(item, str):
            rows.append(item)
        elif "library" in item:
            library = item.get("library", "")
            symbols = item.get("symbols", [])
            if not symbols:
                rows.append(library)
            for symbol in symbols:
                name = symbol.get("name") or f"ordinal_{symbol.get('ordinal')}"
                rows.append(f"{library}!{name}" if library else name)
        elif "module" in item:
            rows.append(f"{item.get('module')}::{item.get('name')}")
        elif "name" in item:
            rows.append(item["name"])
    return rows


def _hex_or_empty(value: int | None) -> str:
    return "" if value is None else f"0x{value:x}"


def _format_export_rows(exports: list) -> list[str]:
    rows = []
    for item in exports:
        if isinstance(item, str):
            rows.append(item)
        elif "name" in item:
            rows.append(item["name"])
    return rows


def write_report_json(case_dir: Path, report: dict) -> Path:
    return _write_json(Path(case_dir) / "report.json", report)


def write_report_html(case_dir: Path, report: dict) -> Path:
    return _write_text(Path(case_dir) / "report.html", render_report_html(report))


def write_summary_md(case_dir: Path, report: dict) -> Path:
    return _write_text(Path(case_dir) / "summary.md", render_summary_md(report))


def write_indicator_exports(case_dir: Path, report: dict) -> list[Path]:
    case_dir = Path(case_dir)
    indicators = report["extraction"]["indicators"]

    csv_path = case_dir / "indicators.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["type", "value", "source"])
        for item in indicators:
            writer.writerow([item["type"], item["value"], item["source"]])

    json_path = _write_json(
        case_dir / "indicators.json",
        {
            "case_id": report["manifest"]["case_id"],
            "count": len(indicators),
            "indicators": indicators,
        },
    )
    return [csv_path, json_path]


def write_all_reports(case_dir: Path, report: dict) -> list[Path]:
    paths = [
        write_report_json(case_dir, report),
        write_report_html(case_dir, report),
        write_summary_md(case_dir, report),
    ]
    paths.extend(write_indicator_exports(case_dir, report))
    return paths
