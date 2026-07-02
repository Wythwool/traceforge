"""Case index and comparison helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from traceforge.annotations import load_annotations

CASE_INDEX_NAME = "case_index.json"


def load_case_report(case_dir: Path) -> dict:
    """Load a stored case report."""
    path = Path(case_dir) / "report.json"
    if not path.is_file():
        raise FileNotFoundError(f"{path} not found")
    return json.loads(path.read_text(encoding="utf-8"))


def case_directories(cases_root: Path) -> list[Path]:
    """Return case folders below a cases root."""
    root = Path(cases_root)
    if not root.is_dir():
        return []
    return sorted(
        entry for entry in root.iterdir() if entry.is_dir() and (entry / "report.json").is_file()
    )


def build_case_index(cases_root: Path) -> dict:
    """Build a compact index for every case below a cases root."""
    root = Path(cases_root)
    cases = []
    errors = []
    for case_dir in case_directories(root):
        try:
            report = load_case_report(case_dir)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append({"case_dir": str(case_dir), "error": str(exc)})
            continue
        cases.append(summarize_case(case_dir, report))

    return {
        "created_utc": _utc_now(),
        "cases_root": str(root),
        "case_count": len(cases),
        "error_count": len(errors),
        "cases": cases,
        "errors": errors,
    }


def write_case_index(cases_root: Path) -> Path:
    """Write case_index.json below the cases root."""
    root = Path(cases_root)
    root.mkdir(parents=True, exist_ok=True)
    path = root / CASE_INDEX_NAME
    _write_json(path, build_case_index(root))
    return path


def summarize_case(case_dir: Path, report: dict) -> dict:
    manifest = report.get("manifest", {})
    extraction = report.get("extraction", {})
    score = report.get("score", {})
    fmt = extraction.get("format", {})
    details = fmt.get("details", {})
    code = extraction.get("code", {})
    strings = extraction.get("strings", {})
    ascii_total = strings.get("ascii", {}).get("total", 0)
    utf16_total = strings.get("utf16le", {}).get("total", 0)
    annotations = _safe_annotations(case_dir)
    return {
        "case_id": manifest.get("case_id", Path(case_dir).name),
        "case_dir": str(Path(case_dir)),
        "file_name": manifest.get("file_name", ""),
        "source_path": manifest.get("source_path", ""),
        "sha256": manifest.get("sha256", extraction.get("hashes", {}).get("sha256", "")),
        "size": manifest.get("size", extraction.get("size", 0)),
        "created_utc": manifest.get("created_utc", ""),
        "format": fmt.get("kind", "raw"),
        "format_confidence": fmt.get("confidence", "low"),
        "score": score.get("score", 0),
        "label": score.get("label", "low"),
        "status": annotations.get("status", "new"),
        "tags": annotations.get("tags", []),
        "note_count": len(annotations.get("notes", [])),
        "annotations_updated_utc": annotations.get("updated_utc", ""),
        "indicator_count": len(extraction.get("indicators", [])),
        "rule_match_count": extraction.get("rules", {}).get("match_count", 0),
        "string_count": ascii_total + utf16_total,
        "section_count": len(details.get("sections", [])),
        "resource_count": len(details.get("resources", [])),
        "debug_entry_count": len(details.get("debug", [])),
        "tls_callback_count": len(details.get("tls", {}).get("callbacks", [])),
        "certificate_count": len(details.get("certificates", [])),
        "import_count": _count_imports(details),
        "export_count": len(details.get("exports", [])),
        "symbol_count": len(extraction.get("symbols", {}).get("symbols", [])),
        "relocation_count": _count_relocations(extraction.get("symbols", {})),
        "code_range_count": len(code.get("ranges", [])),
        "function_count": len(code.get("functions", [])),
        "basic_block_count": len(code.get("basic_blocks", [])),
        "xref_count": len(code.get("xrefs", [])),
        "code_edge_count": len(code.get("edges", [])),
        "embedded_artifact_count": len(fmt.get("embedded", [])),
    }


def diff_cases(left_case_dir: Path, right_case_dir: Path) -> dict:
    """Compare two stored cases and return a structured diff."""
    left_dir = Path(left_case_dir)
    right_dir = Path(right_case_dir)
    left_report = load_case_report(left_dir)
    right_report = load_case_report(right_dir)
    left_extraction = left_report.get("extraction", {})
    right_extraction = right_report.get("extraction", {})
    left_summary = summarize_case(left_dir, left_report)
    right_summary = summarize_case(right_dir, right_report)

    indicators = _diff_values(
        _indicator_values(left_extraction), _indicator_values(right_extraction)
    )
    rule_matches = _diff_values(_rule_ids(left_extraction), _rule_ids(right_extraction))
    imports = _diff_values(_import_values(left_extraction), _import_values(right_extraction))
    exports = _diff_values(_export_values(left_extraction), _export_values(right_extraction))
    sections = _diff_values(_section_values(left_extraction), _section_values(right_extraction))
    resources = _diff_values(
        _resource_values(left_extraction), _resource_values(right_extraction)
    )
    debug_info = _diff_values(
        _debug_values(left_extraction), _debug_values(right_extraction)
    )
    symbols = _diff_values(_symbol_values(left_extraction), _symbol_values(right_extraction))
    relocations = _diff_values(
        _relocation_values(left_extraction), _relocation_values(right_extraction)
    )
    functions = _diff_values(_function_values(left_extraction), _function_values(right_extraction))
    basic_blocks = _diff_values(
        _basic_block_values(left_extraction), _basic_block_values(right_extraction)
    )
    xrefs = _diff_values(_xref_values(left_extraction), _xref_values(right_extraction))
    code_edges = _diff_values(
        _code_edge_values(left_extraction), _code_edge_values(right_extraction)
    )
    certificates = _diff_values(
        _certificate_values(left_extraction), _certificate_values(right_extraction)
    )
    embedded = _diff_values(
        _embedded_values(left_extraction), _embedded_values(right_extraction)
    )

    diff = {
        "created_utc": _utc_now(),
        "left": left_summary,
        "right": right_summary,
        "same_sha256": left_summary["sha256"] == right_summary["sha256"],
        "size_delta": right_summary["size"] - left_summary["size"],
        "score_delta": right_summary["score"] - left_summary["score"],
        "format_changed": left_summary["format"] != right_summary["format"],
        "indicators": indicators,
        "rule_matches": rule_matches,
        "imports": imports,
        "exports": exports,
        "sections": sections,
        "resources": resources,
        "debug_info": debug_info,
        "symbols": symbols,
        "relocations": relocations,
        "functions": functions,
        "basic_blocks": basic_blocks,
        "xrefs": xrefs,
        "code_edges": code_edges,
        "certificates": certificates,
        "embedded_artifacts": embedded,
        "strings": _string_delta(left_extraction, right_extraction),
    }
    diff["summary"] = _diff_summary(diff)
    return diff


def write_case_diff(
    left_case_dir: Path, right_case_dir: Path, output_dir: Path | None = None
) -> list[Path]:
    """Write diff.json and diff.md for two stored cases."""
    diff = diff_cases(left_case_dir, right_case_dir)
    target = Path(output_dir) if output_dir is not None else _default_diff_dir(diff)
    target.mkdir(parents=True, exist_ok=True)
    json_path = target / "diff.json"
    md_path = target / "diff.md"
    _write_json(json_path, diff)
    md_path.write_text(render_diff_markdown(diff), encoding="utf-8")
    return [json_path, md_path]


def render_diff_markdown(diff: dict) -> str:
    left = diff["left"]
    right = diff["right"]
    lines = [
        f"# Case diff: {left['case_id']} -> {right['case_id']}",
        "",
        "## Overview",
        "",
        f"- Left file: `{left['file_name']}`",
        f"- Right file: `{right['file_name']}`",
        f"- Same SHA-256: `{str(diff['same_sha256']).lower()}`",
        f"- Format: `{left['format']}` -> `{right['format']}`",
        f"- Size delta: `{diff['size_delta']}` bytes",
        f"- Score delta: `{diff['score_delta']}`",
        "",
        "## Summary",
        "",
    ]
    lines.extend(f"- {item}" for item in diff.get("summary", []))
    if not diff.get("summary"):
        lines.append("- No meaningful differences were found.")
    lines.extend(
        [
            "",
            "## Indicators",
            "",
            _render_value_counts(diff["indicators"]),
            "",
            "## Rule Matches",
            "",
            _render_value_counts(diff["rule_matches"]),
            "",
            "## Imports",
            "",
            _render_value_counts(diff["imports"]),
            "",
            "## Exports",
            "",
            _render_value_counts(diff["exports"]),
            "",
            "## Sections",
            "",
            _render_value_counts(diff["sections"]),
            "",
            "## Resources",
            "",
            _render_value_counts(diff["resources"]),
            "",
            "## Debug Info",
            "",
            _render_value_counts(diff["debug_info"]),
            "",
            "## Symbols",
            "",
            _render_value_counts(diff["symbols"]),
            "",
            "## Relocations",
            "",
            _render_value_counts(diff["relocations"]),
            "",
            "## Functions",
            "",
            _render_value_counts(diff["functions"]),
            "",
            "## Basic Blocks",
            "",
            _render_value_counts(diff["basic_blocks"]),
            "",
            "## Code Xrefs",
            "",
            _render_value_counts(diff["xrefs"]),
            "",
            "## Code Edges",
            "",
            _render_value_counts(diff["code_edges"]),
            "",
            "## Certificates",
            "",
            _render_value_counts(diff["certificates"]),
            "",
        ]
    )
    return "\n".join(lines)


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _safe_annotations(case_dir: Path) -> dict:
    try:
        return load_annotations(case_dir)
    except (OSError, json.JSONDecodeError, ValueError):
        return {"status": "new", "tags": [], "notes": [], "updated_utc": ""}


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _count_imports(details: dict) -> int:
    total = 0
    for item in details.get("imports", []):
        total += 1
        total += len(item.get("symbols", []))
    return total


def _count_relocations(symbol_info: dict) -> int:
    total = 0
    for block in symbol_info.get("relocations", []):
        total += len(block.get("entries", []))
    return total


def _diff_values(left: set[str], right: set[str]) -> dict:
    added = sorted(right - left)
    removed = sorted(left - right)
    common = sorted(left & right)
    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "common_count": len(common),
        "added": added,
        "removed": removed,
        "common": common[:50],
    }


def _indicator_values(extraction: dict) -> set[str]:
    return {
        f"{item.get('type', '')}:{item.get('value', '')}"
        for item in extraction.get("indicators", [])
    }


def _rule_ids(extraction: dict) -> set[str]:
    return {
        item.get("id", "")
        for item in extraction.get("rules", {}).get("matches", [])
        if item.get("id")
    }


def _import_values(extraction: dict) -> set[str]:
    details = extraction.get("format", {}).get("details", {})
    values = set()
    for item in details.get("imports", []):
        library = item.get("library") or item.get("module") or ""
        name = item.get("name", "")
        if library:
            values.add(library.lower())
        if name:
            values.add(f"{library}::{name}".strip(":").lower())
        for symbol in item.get("symbols", []):
            symbol_name = symbol.get("name", "")
            if symbol_name:
                values.add(f"{library}!{symbol_name}".lower())
    return values


def _export_values(extraction: dict) -> set[str]:
    details = extraction.get("format", {}).get("details", {})
    values = set()
    for item in details.get("exports", []):
        name = item.get("name", "")
        module = item.get("module", "")
        if name:
            values.add(f"{module}!{name}".strip("!").lower())
    return values


def _section_values(extraction: dict) -> set[str]:
    details = extraction.get("format", {}).get("details", {})
    values = set()
    for item in details.get("sections", []):
        name = item.get("name") or item.get("id")
        if name:
            values.add(str(name).lower())
    return values


def _resource_values(extraction: dict) -> set[str]:
    values = set()
    details = extraction.get("format", {}).get("details", {})
    for item in details.get("resources", []):
        values.add(
            f"{item.get('type', '')}:{item.get('name', '')}:"
            f"{item.get('language', '')}:{item.get('sha256', '')}".lower()
        )
    return values


def _debug_values(extraction: dict) -> set[str]:
    values = set()
    details = extraction.get("format", {}).get("details", {})
    for item in details.get("debug", []):
        codeview = item.get("codeview", {})
        values.add(
            f"{item.get('type', '')}:{codeview.get('pdb_path', '')}:"
            f"{codeview.get('guid', '')}:{codeview.get('age', '')}".lower()
        )
    for item in details.get("tls", {}).get("callbacks", []):
        address = item.get("address")
        if isinstance(address, int):
            values.add(f"tls_callback:{address:x}")
    return values


def _symbol_values(extraction: dict) -> set[str]:
    values = set()
    for source in ("imports", "exports", "symbols"):
        for item in extraction.get("symbols", {}).get(source, []):
            name = item.get("name", "")
            kind = item.get("kind", item.get("type", ""))
            if name:
                values.add(f"{source}:{kind}:{name}".lower())
    return values


def _relocation_values(extraction: dict) -> set[str]:
    values = set()
    for block in extraction.get("symbols", {}).get("relocations", []):
        page = block.get("page_rva", 0)
        for entry in block.get("entries", []):
            values.add(f"{page:x}:{entry.get('type', '')}:{entry.get('rva', 0):x}".lower())
    return values


def _function_values(extraction: dict) -> set[str]:
    values = set()
    for item in extraction.get("code", {}).get("functions", []):
        address = item.get("address")
        name = item.get("name", "")
        if isinstance(address, int):
            values.add(f"{address:x}:{name}".lower())
    return values


def _basic_block_values(extraction: dict) -> set[str]:
    values = set()
    for item in extraction.get("code", {}).get("basic_blocks", []):
        address = item.get("address")
        if isinstance(address, int):
            values.add(
                f"{address:x}:{item.get('size', '')}:"
                f"{item.get('instruction_count', '')}:{item.get('terminator', '')}".lower()
            )
    return values


def _xref_values(extraction: dict) -> set[str]:
    values = set()
    for item in extraction.get("code", {}).get("xrefs", []):
        source = item.get("source")
        target = item.get("target")
        if isinstance(source, int) and isinstance(target, int):
            values.add(
                f"{item.get('kind', '')}:{source:x}->{target:x}:"
                f"{item.get('target_kind', '')}:{item.get('target_name', '')}:"
                f"{item.get('indirect', False)}".lower()
            )
    return values


def _code_edge_values(extraction: dict) -> set[str]:
    values = set()
    for item in extraction.get("code", {}).get("edges", []):
        source = item.get("source")
        target = item.get("target")
        if isinstance(source, int) and isinstance(target, int):
            values.add(f"{item.get('kind', '')}:{source:x}->{target:x}".lower())
    return values


def _certificate_values(extraction: dict) -> set[str]:
    values = set()
    details = extraction.get("format", {}).get("details", {})
    for item in details.get("certificates", []):
        values.add(f"{item.get('type', '')}:{item.get('sha256', '')}".lower())
    return values


def _embedded_values(extraction: dict) -> set[str]:
    return {
        f"{item.get('kind', '')}@{item.get('offset', '')}"
        for item in extraction.get("format", {}).get("embedded", [])
    }


def _string_delta(left: dict, right: dict) -> dict:
    left_strings = left.get("strings", {})
    right_strings = right.get("strings", {})
    return {
        "ascii_total_delta": (
            right_strings.get("ascii", {}).get("total", 0)
            - left_strings.get("ascii", {}).get("total", 0)
        ),
        "utf16le_total_delta": (
            right_strings.get("utf16le", {}).get("total", 0)
            - left_strings.get("utf16le", {}).get("total", 0)
        ),
    }


def _diff_summary(diff: dict) -> list[str]:
    lines = []
    if diff["same_sha256"]:
        lines.append("Files have the same SHA-256.")
    else:
        lines.append("Files have different SHA-256 values.")
    if diff["format_changed"]:
        lines.append(
            f"Format changed from {diff['left']['format']} to {diff['right']['format']}."
        )
    if diff["size_delta"]:
        lines.append(f"Size changed by {diff['size_delta']} bytes.")
    if diff["score_delta"]:
        lines.append(f"Score changed by {diff['score_delta']} points.")
    for key, label in (
        ("indicators", "indicator"),
        ("rule_matches", "rule match"),
        ("imports", "import"),
        ("exports", "export"),
        ("sections", "section"),
        ("resources", "resource"),
        ("debug_info", "debug item"),
        ("symbols", "symbol"),
        ("relocations", "relocation"),
        ("functions", "function"),
        ("basic_blocks", "basic block"),
        ("xrefs", "code xref"),
        ("code_edges", "code edge"),
        ("certificates", "certificate"),
        ("embedded_artifacts", "embedded artifact"),
    ):
        item = diff[key]
        if item["added_count"] or item["removed_count"]:
            lines.append(
                f"{item['added_count']} {label}(s) added, "
                f"{item['removed_count']} removed."
            )
    return lines


def _render_value_counts(item: dict) -> str:
    lines = [
        f"- Added: `{item['added_count']}`",
        f"- Removed: `{item['removed_count']}`",
        f"- Common: `{item['common_count']}`",
    ]
    for label in ("added", "removed"):
        values = item[label][:20]
        if values:
            lines.append(f"- {label.title()} values:")
            lines.extend(f"  - `{value}`" for value in values)
    return "\n".join(lines)


def _default_diff_dir(diff: dict) -> Path:
    left = _safe_name(diff["left"]["case_id"])
    right = _safe_name(diff["right"]["case_id"])
    return Path(".traceforge") / "diffs" / f"{left}_vs_{right}"


def _safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)
