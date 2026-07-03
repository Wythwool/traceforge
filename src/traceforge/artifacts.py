"""Workbench artifact writers for stored cases."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from traceforge.api_profile import write_api_profile_csv
from traceforge.callgraph import write_callgraph_csv, write_callgraph_dot
from traceforge.capabilities import write_capabilities_csv
from traceforge.code_map import write_blocks_csv, write_code_csv, write_xrefs_csv
from traceforge.format_profile import write_profile_csv
from traceforge.symbols import write_relocations_csv

DEFAULT_HEXDUMP_LIMIT = 8192


def write_case_artifacts(
    case_dir: Path,
    report: dict,
    source_path: Path | None = None,
    hexdump_limit: int = DEFAULT_HEXDUMP_LIMIT,
) -> list[Path]:
    """Write analyst-friendly files derived from a stored report."""
    target = Path(case_dir)
    target.mkdir(parents=True, exist_ok=True)

    paths = [
        _write_strings_csv(target / "strings.csv", report),
        _write_chunks_csv(target / "chunks.csv", report),
        _write_sections_csv(target / "sections.csv", report),
        _write_resources_csv(target / "resources.csv", report),
        _write_debug_csv(target / "debug.csv", report),
        _write_pe_metadata_csv(target / "pe_metadata.csv", report),
        _write_imports_csv(target / "imports.csv", report),
        _write_exports_csv(target / "exports.csv", report),
        _write_symbols_csv(target / "symbols.csv", report),
        write_relocations_csv(
            target / "relocations.csv",
            report.get("extraction", {}).get("symbols", {}),
        ),
        write_code_csv(target / "code.csv", report.get("extraction", {}).get("code", {})),
        write_blocks_csv(target / "blocks.csv", report.get("extraction", {}).get("code", {})),
        write_xrefs_csv(target / "xrefs.csv", report.get("extraction", {}).get("code", {})),
        write_callgraph_csv(
            target / "callgraph.csv",
            report.get("extraction", {}).get("callgraph", {}),
        ),
        write_callgraph_dot(
            target / "callgraph.dot",
            report.get("extraction", {}).get("callgraph", {}),
        ),
        _write_signature_matches_csv(target / "signature_matches.csv", report),
        write_capabilities_csv(
            target / "capabilities.csv",
            report.get("extraction", {}).get("capabilities", {}),
        ),
        write_profile_csv(
            target / "format_profile.csv",
            report.get("extraction", {}).get("profile", {}),
        ),
        write_api_profile_csv(
            target / "api_profile.csv",
            report.get("extraction", {}).get("apis", {}),
        ),
        _write_findings_csv(target / "findings.csv", report),
    ]

    source = _case_source(report, source_path)
    hexdump = {"written": False, "source_path": str(source) if source else ""}
    if source is not None and source.is_file() and hexdump_limit > 0:
        data = source.read_bytes()[:hexdump_limit]
        paths.append(_write_text(target / "hexdump.txt", render_hexdump(data)))
        hexdump = {
            "written": True,
            "source_path": str(source),
            "bytes": len(data),
            "limit": hexdump_limit,
        }
    else:
        paths.append(_write_text(target / "hexdump.txt", ""))

    manifest = {
        "case_id": report.get("manifest", {}).get("case_id", target.name),
        "files": [path.name for path in paths],
        "hexdump": hexdump,
    }
    paths.append(_write_json(target / "artifacts.json", manifest))
    return paths


def render_hexdump(data: bytes, width: int = 16) -> str:
    """Render bytes in a classic offset/hex/ascii layout."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        left = " ".join(f"{byte:02x}" for byte in chunk)
        left = left.ljust(width * 3 - 1)
        text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {left}  |{text}|")
    return "\n".join(lines) + ("\n" if lines else "")


def _case_source(report: dict, source_path: Path | None) -> Path | None:
    if source_path is not None:
        return Path(source_path)
    value = report.get("manifest", {}).get("source_path")
    return Path(value) if value else None


def _write_strings_csv(path: Path, report: dict) -> Path:
    strings = report["extraction"]["strings"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source", "index", "length", "value"])
        for source in ("ascii", "utf16le"):
            for index, value in enumerate(strings.get(source, {}).get("values", [])):
                writer.writerow([source, index, len(value), value])
    return path


def _write_chunks_csv(path: Path, report: dict) -> Path:
    records = report["extraction"]["chunks"]["records"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["index", "offset", "size", "entropy"])
        for record in records:
            writer.writerow(
                [
                    record.get("index", ""),
                    record.get("offset", ""),
                    record.get("size", ""),
                    record.get("entropy", ""),
                ]
            )
    return path


def _write_sections_csv(path: Path, report: dict) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "index",
                "name",
                "offset",
                "size",
                "virtual_address",
                "virtual_size",
                "flags",
                "readable",
                "writable",
                "executable",
            ]
        )
        for section in _sections(report):
            writer.writerow(
                [
                    section.get("index", ""),
                    section.get("name", section.get("label", "")),
                    section.get("raw_offset", section.get("offset", section.get("fileoff", ""))),
                    section.get("raw_size", section.get("size", section.get("filesize", ""))),
                    section.get("virtual_address", section.get("address", "")),
                    section.get("virtual_size", ""),
                    section.get("characteristics", section.get("flags", "")),
                    section.get("readable", ""),
                    section.get("writable", ""),
                    section.get("executable", ""),
                ]
            )
    return path


def _write_resources_csv(path: Path, report: dict) -> Path:
    resources = (
        report.get("extraction", {})
        .get("format", {})
        .get("details", {})
        .get("resources", [])
    )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["type", "type_id", "name", "language", "offset", "size", "sha256", "preview"]
        )
        for item in resources:
            writer.writerow(
                [
                    item.get("type", ""),
                    item.get("type_id", ""),
                    item.get("name", ""),
                    item.get("language", ""),
                    item.get("offset", ""),
                    item.get("size", ""),
                    item.get("sha256", ""),
                    item.get("preview", ""),
                ]
            )
    return path


def _write_debug_csv(path: Path, report: dict) -> Path:
    details = report.get("extraction", {}).get("format", {}).get("details", {})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source", "type", "offset", "size", "detail"])
        for item in details.get("debug", []):
            codeview = item.get("codeview", {})
            writer.writerow(
                [
                    "debug",
                    item.get("type", ""),
                    item.get("offset", ""),
                    item.get("size", ""),
                    codeview.get("pdb_path", codeview.get("format", "")),
                ]
            )
        for item in details.get("tls", {}).get("callbacks", []):
            writer.writerow(
                [
                    "tls_callback",
                    "",
                    item.get("rva", ""),
                    "",
                    f"0x{item.get('address', 0):x}",
                ]
            )
        for item in details.get("certificates", []):
            writer.writerow(
                [
                    "certificate",
                    item.get("type", ""),
                    item.get("offset", ""),
                    item.get("size", ""),
                    item.get("sha256", ""),
                ]
            )
    return path


def _write_pe_metadata_csv(path: Path, report: dict) -> Path:
    details = report.get("extraction", {}).get("format", {}).get("details", {})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source", "name", "value", "detail"])

        def emit(source: str, name: str, value: object = "", detail: str = "") -> None:
            writer.writerow([source, name, _cell(value), detail])

        load_config = details.get("load_config", {})
        if load_config:
            for key in (
                "rva",
                "offset",
                "size",
                "timestamp",
                "version",
                "global_flags_clear",
                "global_flags_set",
                "process_heap_flags",
                "dependent_load_flags",
                "guard_flags",
                "se_handler_count",
                "guard_cf_function_count",
            ):
                if key in load_config:
                    emit("load_config", key, load_config.get(key, ""))
            for key in (
                "security_cookie",
                "se_handler_table",
                "guard_cf_check_function",
                "guard_cf_dispatch_function",
                "guard_cf_function_table",
            ):
                record = load_config.get(key, {})
                if record:
                    emit("load_config", key, _address_cell(record), _address_detail(record))
            for name in load_config.get("guard_flag_names", []):
                emit("load_config.guard", name, "true")

        exceptions = details.get("exceptions", {})
        if exceptions:
            emit(
                "exceptions",
                "count",
                exceptions.get("count", 0),
                f"truncated={exceptions.get('truncated', False)}",
            )
            for item in exceptions.get("entries", []):
                value = (
                    f"{_hex_cell(item.get('begin_rva'))}-"
                    f"{_hex_cell(item.get('end_rva'))}"
                )
                detail = (
                    f"unwind={_hex_cell(item.get('unwind_info_rva'))}; "
                    f"section={item.get('begin_section', '')}"
                )
                emit("exception", f"entry_{item.get('index', '')}", value, detail)

        for item in details.get("delay_imports", []):
            library = item.get("library", "")
            emit(
                "delay_import",
                library,
                f"symbols={len(item.get('symbols', []))}",
                (
                    f"iat={_hex_cell(item.get('iat_rva'))}; "
                    f"name_table={_hex_cell(item.get('name_table_rva'))}"
                ),
            )
            for symbol in item.get("symbols", []):
                name = symbol.get("name") or f"ordinal_{symbol.get('ordinal', '')}"
                detail = (
                    f"ordinal={symbol.get('ordinal', '')}; "
                    f"iat={_hex_cell(symbol.get('iat_rva'))}; "
                    f"thunk={_hex_cell(symbol.get('thunk_rva'))}"
                )
                emit("delay_import.symbol", f"{library}!{name}", name, detail)

        clr = details.get("clr", {})
        if clr:
            for key in ("runtime_version", "flags", "entry_point_token"):
                if key in clr:
                    emit("clr", key, clr.get(key, ""))
            for name in clr.get("flag_names", []):
                emit("clr.flag", name, "true")
            metadata = clr.get("metadata", {})
            if metadata:
                for key in ("metadata_version", "version", "stream_count"):
                    if key in metadata:
                        emit("clr.metadata", key, metadata.get(key, ""))
                for stream in metadata.get("streams", []):
                    emit(
                        "clr.stream",
                        stream.get("name", ""),
                        stream.get("size", ""),
                        f"offset={_hex_cell(stream.get('offset'))}",
                    )
    return path


def _write_imports_csv(path: Path, report: dict) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["library", "module", "name", "kind", "ordinal", "iat_rva", "iat_address"])
        for row in _import_rows(report):
            writer.writerow(row)
    return path


def _write_exports_csv(path: Path, report: dict) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["module", "name", "kind", "index", "ordinal"])
        for row in _export_rows(report):
            writer.writerow(row)
    return path


def _write_symbols_csv(path: Path, report: dict) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source", "name", "kind", "binding", "section", "value", "size"])
        for source in ("imports", "exports", "symbols"):
            for item in _symbol_rows(report, source):
                writer.writerow(
                    [
                        source,
                        item.get("name", ""),
                        item.get("kind", item.get("type", "")),
                        item.get("binding", ""),
                        item.get("section", item.get("section_index", "")),
                        item.get("value", ""),
                        item.get("size", ""),
                    ]
                )
    return path


def _write_findings_csv(path: Path, report: dict) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source", "id", "level", "name", "detail", "evidence"])
        for reason in report.get("score", {}).get("reasons", []):
            writer.writerow(
                [
                    "score",
                    reason.get("signal", ""),
                    "",
                    reason.get("signal", ""),
                    reason.get("detail", ""),
                    "; ".join(reason.get("evidence", [])),
                ]
            )
        for match in report.get("extraction", {}).get("rules", {}).get("matches", []):
            writer.writerow(
                [
                    "rule",
                    match.get("id", ""),
                    match.get("level", ""),
                    match.get("name", ""),
                    match.get("description", ""),
                    "; ".join(match.get("evidence", [])),
                ]
            )
        for match in report.get("extraction", {}).get("signatures", {}).get("matches", []):
            writer.writerow(
                [
                    "signature",
                    match.get("id", ""),
                    match.get("level", ""),
                    match.get("name", ""),
                    match.get("description", ""),
                    "; ".join(match.get("evidence", [])),
                ]
            )
        for item in report.get("extraction", {}).get("capabilities", {}).get("categories", []):
            writer.writerow(
                [
                    "capability",
                    item.get("id", ""),
                    item.get("confidence", ""),
                    item.get("name", ""),
                    item.get("description", ""),
                    "; ".join(
                        f"{evidence.get('source', '')}:{evidence.get('value', '')}"
                        for evidence in item.get("evidence", [])[:10]
                    ),
                ]
            )
        for item in report.get("extraction", {}).get("profile", {}).get("observations", []):
            writer.writerow(
                [
                    "profile",
                    item.get("id", ""),
                    item.get("level", ""),
                    item.get("title", ""),
                    item.get("detail", ""),
                    item.get("evidence", ""),
                ]
            )
        for item in report.get("extraction", {}).get("apis", {}).get("families", []):
            writer.writerow(
                [
                    "api",
                    item.get("id", ""),
                    item.get("confidence", ""),
                    item.get("name", ""),
                    item.get("description", ""),
                    "; ".join(
                        f"{evidence.get('library', '')}:{evidence.get('name', '')}"
                        for evidence in item.get("evidence", [])[:10]
                    ),
                ]
            )
        for item in _observations(report):
            writer.writerow(
                [
                    "format",
                    item.get("id", ""),
                    "",
                    item.get("id", ""),
                    item.get("detail", ""),
                    str(item.get("evidence", "")),
                ]
            )
    return path


def _write_signature_matches_csv(path: Path, report: dict) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "signature_id",
                "level",
                "name",
                "pattern_id",
                "type",
                "offset",
                "offset_hex",
                "section",
                "value",
            ]
        )
        for signature in report.get("extraction", {}).get("signatures", {}).get("matches", []):
            for pattern in signature.get("patterns", []):
                for match in pattern.get("matches", []):
                    writer.writerow(
                        [
                            signature.get("id", ""),
                            signature.get("level", ""),
                            signature.get("name", ""),
                            pattern.get("id", ""),
                            match.get("type", ""),
                            match.get("offset", ""),
                            match.get("offset_hex", ""),
                            match.get("section", ""),
                            match.get("value", ""),
                        ]
                    )
    return path


def _sections(report: dict) -> list[dict]:
    details = report.get("extraction", {}).get("format", {}).get("details", {})
    return details.get("sections", []) or details.get("segments", [])


def _observations(report: dict) -> list[dict]:
    return (
        report.get("extraction", {})
        .get("format", {})
        .get("details", {})
        .get("observations", [])
    )


def _symbol_rows(report: dict, source: str) -> list[dict]:
    return (
        report.get("extraction", {})
        .get("symbols", {})
        .get(source, [])
    )


def _import_rows(report: dict) -> list[list[object]]:
    details = (
        report.get("extraction", {})
        .get("format", {})
        .get("details", {})
    )
    imports = details.get("imports", [])
    rows = []
    for item in imports:
        if isinstance(item, str):
            rows.append([item, "", "", "", "", "", ""])
        elif "library" in item:
            library = item.get("library", "")
            symbols = item.get("symbols", [])
            if not symbols:
                rows.append([library, "", "", "", "", "", ""])
            for symbol in symbols:
                rows.append(
                    [
                        library,
                        "",
                        symbol.get("name", ""),
                        "",
                        symbol.get("ordinal", ""),
                        symbol.get("iat_rva", ""),
                        symbol.get("iat_address", ""),
                    ]
                )
        else:
            rows.append(
                [
                    "",
                    item.get("module", ""),
                    item.get("name", ""),
                    item.get("kind", ""),
                    item.get("ordinal", ""),
                    "",
                    "",
                ]
            )
    for item in details.get("delay_imports", []):
        library = item.get("library", "")
        symbols = item.get("symbols", [])
        if not symbols:
            rows.append([library, "", "", "delay", "", item.get("iat_rva", ""), ""])
        for symbol in symbols:
            rows.append(
                [
                    library,
                    "",
                    symbol.get("name", ""),
                    "delay",
                    symbol.get("ordinal", ""),
                    symbol.get("iat_rva", ""),
                    symbol.get("iat_address", ""),
                ]
            )
    return rows


def _export_rows(report: dict) -> list[list[object]]:
    exports = (
        report.get("extraction", {})
        .get("format", {})
        .get("details", {})
        .get("exports", [])
    )
    rows = []
    for item in exports:
        if isinstance(item, str):
            rows.append(["", item, "", "", ""])
        else:
            rows.append(
                [
                    item.get("module", ""),
                    item.get("name", ""),
                    item.get("kind", ""),
                    item.get("index", ""),
                    item.get("ordinal", ""),
                ]
            )
    return rows


def _write_json(path: Path, payload: dict) -> Path:
    return _write_text(path, json.dumps(payload, indent=2) + "\n")


def _write_text(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _cell(value: object) -> object:
    return _hex_cell(value) if isinstance(value, int) else value


def _hex_cell(value: object) -> str:
    return f"0x{value:x}" if isinstance(value, int) else str(value or "")


def _address_cell(record: dict) -> str:
    return _hex_cell(record.get("address"))


def _address_detail(record: dict) -> str:
    parts = []
    if record.get("rva") is not None:
        parts.append(f"rva={_hex_cell(record.get('rva'))}")
    if record.get("offset") is not None:
        parts.append(f"offset={_hex_cell(record.get('offset'))}")
    if record.get("section"):
        parts.append(f"section={record.get('section')}")
    return "; ".join(parts)
