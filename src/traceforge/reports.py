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

    lines = [
        f"# TraceForge summary: {manifest['file_name']}",
        "",
        f"- Case: `{manifest['case_id']}`",
        f"- Source: `{manifest['source_path']}`",
        f"- Size: {extraction['size']} bytes",
        f"- SHA-256: `{extraction['hashes']['sha256']}`",
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
