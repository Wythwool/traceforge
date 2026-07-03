"""Analyst-oriented format profiling for local file metadata."""

from __future__ import annotations

import csv
import json
from pathlib import Path

MAX_PROFILE_OBSERVATIONS = 256
MAX_PROFILE_SECTIONS = 128
MAX_PROFILE_LIBRARIES = 128

LEVEL_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def build_format_profile(extraction: dict, filename: str = "") -> dict:
    """Build a compact profile from parsed format, symbol, and code facts."""
    format_info = extraction.get("format", {})
    details = format_info.get("details", {})
    kind = format_info.get("kind", "raw")
    symbols = extraction.get("symbols", {})
    code = extraction.get("code", {})
    callgraph = extraction.get("callgraph", {})

    observations: list[dict] = []
    if kind == "pe":
        _profile_pe(details, observations)
    elif kind == "elf":
        _profile_elf(details, symbols, observations)
    elif kind == "macho":
        _profile_macho(details, observations)
    elif kind in {"zip", "apk", "jar"}:
        _profile_container(details, observations)
    elif kind == "wasm":
        _profile_wasm(details, observations)

    for item in format_info.get("embedded", []):
        _add(
            observations,
            "format.embedded-artifact",
            "medium",
            "Embedded format marker",
            f"{item.get('kind', 'unknown')} marker inside the file",
            f"offset={item.get('offset', '')}",
        )
    if callgraph.get("import_call_count", 0):
        _add(
            observations,
            "code.import-callgraph",
            "info",
            "Import calls resolved",
            "code cross-references include calls to imported functions",
            str(callgraph.get("import_call_count", 0)),
        )

    section_rows = _section_rows(details)
    libraries = _library_rows(details, symbols)
    summary = {
        "section_count": len(section_rows),
        "library_count": len(libraries),
        "import_count": _count_imports(details.get("imports", []))
        or len(symbols.get("imports", [])),
        "export_count": _count_exports(details.get("exports", []))
        or len(symbols.get("exports", [])),
        "resource_count": len(details.get("resources", [])),
        "debug_entry_count": len(details.get("debug", [])),
        "certificate_count": len(details.get("certificates", [])),
        "embedded_count": len(format_info.get("embedded", [])),
        "code_range_count": len(code.get("ranges", [])),
        "function_count": len(code.get("functions", [])),
        "xref_count": len(code.get("xrefs", [])),
        "callgraph_edge_count": callgraph.get("edge_count", 0),
        "import_call_count": callgraph.get("import_call_count", 0),
    }

    return {
        "engine": "traceforge-format-profile",
        "file_name": filename,
        "format": kind,
        "confidence": format_info.get("confidence", "low"),
        "highest_level": _highest_level(observations),
        "summary": summary,
        "observations": observations[:MAX_PROFILE_OBSERVATIONS],
        "sections": section_rows[:MAX_PROFILE_SECTIONS],
        "libraries": libraries[:MAX_PROFILE_LIBRARIES],
        "entry_point": _entry_point(details, kind),
    }


def write_profile_csv(path: Path, payload: dict) -> Path:
    """Write format profile observations as a compact CSV table."""
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "level", "title", "detail", "evidence"])
        for item in payload.get("observations", []):
            writer.writerow(
                [
                    item.get("id", ""),
                    item.get("level", ""),
                    item.get("title", ""),
                    item.get("detail", ""),
                    item.get("evidence", ""),
                ]
            )
    return Path(path)


def dumps(payload: dict) -> str:
    """Render stable JSON for CLI output."""
    return json.dumps(payload, indent=2) + "\n"


def _profile_pe(details: dict, observations: list[dict]) -> None:
    dll_flags = set(details.get("dll_characteristic_flags", []))
    directories = details.get("directories", {})
    sections = details.get("sections", [])
    imports = details.get("imports", [])
    overlay = details.get("overlay", {})

    if "dynamic_base" not in dll_flags:
        _add(
            observations,
            "pe.aslr-missing",
            "medium",
            "ASLR flag not present",
            "dynamic_base is not set in DLL characteristics",
            "dll_characteristic_flags",
        )
    if "nx_compat" not in dll_flags:
        _add(
            observations,
            "pe.nx-missing",
            "medium",
            "NX compatibility flag not present",
            "nx_compat is not set in DLL characteristics",
            "dll_characteristic_flags",
        )
    if "guard_cf" in dll_flags:
        _add(
            observations,
            "pe.guard-cf",
            "info",
            "Control Flow Guard flag present",
            "guard_cf is set in DLL characteristics",
            "dll_characteristic_flags",
        )

    for section in sections:
        name = section.get("name", "")
        if _is_wx(section):
            _add(
                observations,
                "pe.section-wx",
                "high",
                "Writable executable section",
                f"section {name} is both writable and executable",
                name,
            )
        entropy = section.get("entropy", 0)
        if section.get("executable") and isinstance(entropy, int | float) and entropy >= 7.0:
            _add(
                observations,
                "pe.section-high-entropy-exec",
                "medium",
                "High entropy executable section",
                f"section {name} entropy is {entropy}",
                name,
            )

    for item in details.get("observations", []):
        _add(
            observations,
            item.get("id", "pe.observation"),
            _pe_observation_level(item.get("id", "")),
            "PE parser observation",
            item.get("detail", ""),
            str(item.get("evidence", "")),
        )

    if details.get("tls", {}).get("callbacks"):
        _add(
            observations,
            "pe.tls-callbacks",
            "medium",
            "TLS callbacks",
            "TLS callback table is present",
            str(len(details.get("tls", {}).get("callbacks", []))),
        )
    if details.get("debug"):
        _add(
            observations,
            "pe.debug-records",
            "info",
            "Debug records",
            "debug directory records are present",
            str(len(details.get("debug", []))),
        )
    if details.get("certificates"):
        _add(
            observations,
            "pe.certificate-table",
            "info",
            "Certificate table",
            "certificate table records are present",
            str(len(details.get("certificates", []))),
        )
    if directories.get("delay_import"):
        _add(
            observations,
            "pe.delay-imports",
            "info",
            "Delay import directory",
            "delay import directory is present",
            "delay_import",
        )
    if _count_imports(imports) == 0 and sections:
        _add(
            observations,
            "pe.no-resolved-imports",
            "low",
            "No resolved imports",
            "no import names were resolved from the PE import table",
            "imports",
        )
    if overlay.get("present"):
        level = "medium" if overlay.get("entropy", 0) >= 7.0 else "low"
        _add(
            observations,
            "pe.overlay",
            level,
            "Overlay data",
            f"overlay size is {overlay.get('size', 0)} bytes",
            f"offset={overlay.get('offset', 0)}",
        )


def _profile_elf(details: dict, symbols: dict, observations: list[dict]) -> None:
    dynamic = details.get("dynamic", {})
    for section in details.get("sections", []):
        name = section.get("name", "")
        permissions = section.get("permissions", "")
        if "w" in permissions and "x" in permissions:
            _add(
                observations,
                "elf.section-wx",
                "high",
                "Writable executable section",
                f"section {name} is both writable and executable",
                name,
            )

    headers = details.get("program_headers", [])
    has_relro = False
    for header in headers:
        type_name = header.get("type_name", "")
        permissions = header.get("permissions", "")
        has_relro = has_relro or type_name == "gnu_relro"
        if "w" in permissions and "x" in permissions:
            _add(
                observations,
                "elf.segment-wx",
                "high",
                "Writable executable segment",
                f"program header {header.get('index', '')} has write and execute permissions",
                str(header.get("index", "")),
            )
        if type_name == "gnu_stack" and "x" in permissions:
            _add(
                observations,
                "elf.executable-stack",
                "high",
                "Executable stack",
                "GNU stack program header is executable",
                "PT_GNU_STACK",
            )
    if headers and not has_relro:
        _add(
            observations,
            "elf.relro-not-visible",
            "low",
            "RELRO header not visible",
            "no GNU RELRO program header was parsed",
            "program_headers",
        )
    if symbols.get("needed_libraries"):
        _add(
            observations,
            "elf.needed-libraries",
            "info",
            "Needed libraries",
            "dynamic library dependencies are present",
            ", ".join(symbols.get("needed_libraries", [])[:8]),
        )
    if dynamic.get("soname"):
        _add(
            observations,
            "elf.soname",
            "info",
            "Shared object name",
            "ELF dynamic section exposes a SONAME",
            dynamic["soname"],
        )
    if dynamic.get("runpath") or dynamic.get("rpath"):
        value = dynamic.get("runpath") or dynamic.get("rpath")
        _add(
            observations,
            "elf.runtime-search-path",
            "low",
            "Runtime library search path",
            "ELF dynamic section contains RUNPATH or RPATH",
            value,
        )
    relocation_count = sum(
        len(block.get("entries", []))
        for block in symbols.get("relocations", [])
    )
    if relocation_count:
        _add(
            observations,
            "elf.relocations",
            "info",
            "Relocation records",
            "ELF relocation sections are present",
            str(relocation_count),
        )
    if not symbols.get("symbols") and details.get("section_count", 0):
        _add(
            observations,
            "elf.no-symbol-table",
            "low",
            "No visible symbol table",
            "no ELF symbols were resolved from the parsed sections",
            "symbols",
        )


def _profile_macho(details: dict, observations: list[dict]) -> None:
    command_names = {item.get("name") for item in details.get("load_commands", [])}
    if "LC_CODE_SIGNATURE" in command_names:
        _add(
            observations,
            "macho.code-signature",
            "info",
            "Code signature command",
            "LC_CODE_SIGNATURE load command is present",
            "load_commands",
        )
    elif details.get("load_commands"):
        _add(
            observations,
            "macho.code-signature-missing",
            "low",
            "No code signature command",
            "LC_CODE_SIGNATURE load command was not parsed",
            "load_commands",
        )

    for segment in details.get("segments", []):
        protections = set(segment.get("initial_protection", []))
        if {"write", "execute"} <= protections:
            _add(
                observations,
                "macho.segment-wx",
                "high",
                "Writable executable segment",
                f"segment {segment.get('name', '')} has write and execute protections",
                segment.get("name", ""),
            )
    if details.get("linked_libraries"):
        _add(
            observations,
            "macho.linked-libraries",
            "info",
            "Linked libraries",
            "dylib load commands are present",
            ", ".join(details.get("linked_libraries", [])[:8]),
        )


def _profile_container(details: dict, observations: list[dict]) -> None:
    entries = details.get("entries", [])
    for entry in entries:
        name = entry.get("name", "")
        normalized = name.replace("\\", "/")
        if normalized.startswith("/") or "../" in f"/{normalized}":
            _add(
                observations,
                "container.unsafe-path",
                "high",
                "Unsafe archive path",
                "archive entry uses an absolute or parent-relative path",
                name,
            )
    if details.get("entries_truncated"):
        _add(
            observations,
            "container.entries-truncated",
            "info",
            "Container listing truncated",
            "entry list hit the display cap",
            str(details.get("entry_count", "")),
        )
    apk = details.get("apk", {})
    if apk.get("dex_count"):
        _add(
            observations,
            "apk.dex-files",
            "info",
            "DEX files",
            "APK or archive contains DEX files",
            str(apk.get("dex_count")),
        )
    if apk.get("native_library_count"):
        _add(
            observations,
            "apk.native-libraries",
            "medium",
            "Native libraries",
            "APK contains native shared libraries",
            str(apk.get("native_library_count")),
        )
    if apk.get("permissions"):
        _add(
            observations,
            "apk.permissions",
            "info",
            "Android permissions",
            "Android permission strings were parsed",
            ", ".join(apk.get("permissions", [])[:8]),
        )


def _profile_wasm(details: dict, observations: list[dict]) -> None:
    imports = details.get("imports", [])
    exports = details.get("exports", [])
    if imports:
        _add(
            observations,
            "wasm.imports",
            "info",
            "WASM imports",
            "WASM import section is present",
            str(len(imports)),
        )
    if exports:
        _add(
            observations,
            "wasm.exports",
            "info",
            "WASM exports",
            "WASM export section is present",
            str(len(exports)),
        )
    if any(section.get("name") == "start" for section in details.get("sections", [])):
        _add(
            observations,
            "wasm.start-section",
            "low",
            "WASM start section",
            "module has a start section",
            "start",
        )


def _section_rows(details: dict) -> list[dict]:
    rows = []
    source = details.get("sections", []) or details.get("segments", [])
    for index, section in enumerate(source):
        rows.append(
            {
                "index": section.get("index", index),
                "name": section.get("name", section.get("label", "")),
                "offset": section.get(
                    "raw_offset",
                    section.get("offset", section.get("fileoff", 0)),
                ),
                "size": section.get("raw_size", section.get("size", section.get("filesize", 0))),
                "virtual_address": section.get(
                    "virtual_address",
                    section.get("address", section.get("virtual_address", 0)),
                ),
                "permissions": section.get(
                    "permissions",
                    _permissions_from_section(section),
                ),
                "entropy": section.get("entropy", ""),
            }
        )
    return rows


def _library_rows(details: dict, symbols: dict) -> list[dict]:
    values = []
    for item in details.get("imports", []):
        library = item if isinstance(item, str) else item.get("library", "")
        if library:
            values.append(library)
    values.extend(details.get("linked_libraries", []))
    values.extend(details.get("needed_libraries", []))
    values.extend(symbols.get("needed_libraries", []))
    rows = []
    seen = set()
    for value in values:
        key = str(value).lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append({"name": value})
    return rows


def _entry_point(details: dict, kind: str) -> dict:
    if kind == "pe":
        return {
            "address": (
                details.get("image_base", 0) + details["entry_point_rva"]
                if isinstance(details.get("entry_point_rva"), int)
                else None
            ),
            "rva": details.get("entry_point_rva"),
            "section": details.get("entry_section"),
        }
    if kind == "elf":
        return {
            "address": details.get("entry") if isinstance(details.get("entry"), int) else None,
            "section": details.get("entry_section"),
        }
    return {"address": None, "section": None}


def _count_imports(imports: list) -> int:
    count = 0
    for item in imports:
        if isinstance(item, str):
            count += 1
        elif "symbols" in item:
            count += max(1, len(item.get("symbols", [])))
        else:
            count += 1
    return count


def _count_exports(exports: list) -> int:
    return len(exports)


def _is_wx(section: dict) -> bool:
    permissions = section.get("permissions", "")
    return (
        ("w" in permissions and "x" in permissions)
        or bool(section.get("writable") and section.get("executable"))
    )


def _permissions_from_section(section: dict) -> str:
    permissions = section.get("initial_protection") or section.get("max_protection") or []
    if permissions:
        return "".join(
            (
                "r" if "read" in permissions else "-",
                "w" if "write" in permissions else "-",
                "x" if "execute" in permissions else "-",
            )
        )
    return ""


def _pe_observation_level(identifier: str) -> str:
    if identifier in {
        "pe_writable_executable_section",
        "pe_entry_in_non_executable_section",
    }:
        return "high"
    if identifier in {"pe_tls_callbacks", "pe_import_directory_unparsed"}:
        return "medium"
    return "low"


def _highest_level(observations: list[dict]) -> str:
    level = "info"
    for item in observations:
        item_level = item.get("level", "info")
        if LEVEL_ORDER.get(item_level, 0) > LEVEL_ORDER[level]:
            level = item_level
    return level


def _add(
    observations: list[dict],
    identifier: str,
    level: str,
    title: str,
    detail: str,
    evidence: str,
) -> None:
    observations.append(
        {
            "id": identifier,
            "level": level,
            "title": title,
            "detail": detail,
            "evidence": evidence,
        }
    )
