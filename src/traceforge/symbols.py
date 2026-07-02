"""Symbol and relocation inspection for executable files."""

from __future__ import annotations

import csv
import json
import struct
from pathlib import Path

from traceforge.core_types import AnalysisError
from traceforge.formats import analyze_format

MAX_SYMBOLS = 1024
MAX_RELOCATIONS = 1024

PE_RELOCATION_TYPES = {
    0: "absolute",
    1: "high",
    2: "low",
    3: "highlow",
    4: "highadj",
    7: "arm_mov32",
    10: "dir64",
}

ELF_SYMBOL_BINDINGS = {0: "local", 1: "global", 2: "weak"}
ELF_SYMBOL_TYPES = {
    0: "none",
    1: "object",
    2: "function",
    3: "section",
    4: "file",
    5: "common",
    6: "tls",
}
ELF_DYNAMIC_TAGS = {0: "null", 1: "needed", 14: "soname", 15: "rpath", 29: "runpath"}


def inspect_symbols_file(path: Path) -> dict:
    """Inspect symbol-oriented metadata from one local file."""
    path = Path(path)
    return inspect_symbols(path.read_bytes(), path.name)


def inspect_symbols(data: bytes, filename: str = "") -> dict:
    """Return symbols, imports, exports, libraries, and relocations when visible."""
    format_info = analyze_format(data, filename)
    kind = format_info.get("kind", "raw")
    details = format_info.get("details", {})
    payload = {
        "file_name": filename,
        "format": kind,
        "symbols": [],
        "imports": [],
        "exports": [],
        "needed_libraries": [],
        "relocations": [],
    }
    try:
        if kind == "pe":
            payload.update(_inspect_pe(data, details))
        elif kind == "elf":
            payload.update(_inspect_elf(data, details))
        elif kind == "macho":
            payload.update(_inspect_macho(data))
    except AnalysisError as exc:
        payload["error"] = str(exc)
    return payload


def write_symbols_csv(path: Path, payload: dict) -> Path:
    """Write a flat symbol table for spreadsheet review."""
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source", "name", "kind", "binding", "section", "value", "size"])
        for source in ("imports", "exports", "symbols"):
            for item in payload.get(source, []):
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
    return Path(path)


def _inspect_pe(data: bytes, details: dict) -> dict:
    if len(data) < 0x40:
        raise AnalysisError("PE file is too small for symbol inspection")
    e_lfanew = _u32(data, 0x3C)
    coff = e_lfanew + 4
    if coff + 20 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise AnalysisError("PE signature not found")
    symbol_offset = _u32(data, coff + 8)
    symbol_count = _u32(data, coff + 12)
    symbols = _parse_pe_coff_symbols(data, symbol_offset, symbol_count)
    relocations = _parse_pe_relocations(
        data,
        details.get("sections", []),
        details.get("directories", {}).get("base_relocation"),
    )
    return {"symbols": symbols, "relocations": relocations}


def _parse_pe_coff_symbols(data: bytes, offset: int, count: int) -> list[dict]:
    if offset <= 0 or count <= 0:
        return []
    symbols = []
    string_table = offset + count * 18
    string_table_size = _u32(data, string_table) if string_table + 4 <= len(data) else 0
    index = 0
    while index < min(count, MAX_SYMBOLS):
        item = offset + index * 18
        if item + 18 > len(data):
            break
        raw_name, value, section, symbol_type, storage_class, aux_count = struct.unpack_from(
            "<8sIhHBB", data, item
        )
        symbols.append(
            {
                "index": index,
                "name": _coff_name(data, raw_name, string_table, string_table_size),
                "kind": f"0x{symbol_type:04x}",
                "binding": f"storage_{storage_class}",
                "section": section,
                "value": value,
                "size": "",
            }
        )
        index += aux_count + 1
    return symbols


def _parse_pe_relocations(data: bytes, sections: list[dict], directory: dict | None) -> list[dict]:
    if not directory or not directory.get("rva") or not directory.get("size"):
        return []
    offset = _rva_to_offset(sections, directory["rva"])
    if offset is None:
        return []
    end = min(offset + directory["size"], len(data))
    blocks = []
    cursor = offset
    while cursor + 8 <= end and len(blocks) < MAX_RELOCATIONS:
        page_rva, block_size = struct.unpack_from("<II", data, cursor)
        if block_size < 8 or cursor + block_size > end:
            break
        entries = []
        for index in range(min((block_size - 8) // 2, MAX_RELOCATIONS)):
            raw = _u16(data, cursor + 8 + index * 2)
            kind = raw >> 12
            offset_in_page = raw & 0x0FFF
            entries.append(
                {
                    "type": PE_RELOCATION_TYPES.get(kind, f"0x{kind:x}"),
                    "offset": offset_in_page,
                    "rva": page_rva + offset_in_page,
                }
            )
        blocks.append({"page_rva": page_rva, "entries": entries})
        cursor += block_size
    return blocks


def _inspect_elf(data: bytes, details: dict) -> dict:
    if len(data) < 0x34 or not data.startswith(b"\x7fELF"):
        raise AnalysisError("ELF header not found")
    endian = "<" if data[5] == 1 else ">"
    is_64 = data[4] == 2
    sections = details.get("sections", [])
    symbols = _parse_elf_symbols(data, endian, is_64, sections)
    dynamic = _parse_elf_dynamic(data, endian, is_64, sections)
    return {
        "symbols": symbols,
        "imports": _undefined_symbols(symbols),
        "exports": _defined_exports(symbols),
        "needed_libraries": dynamic["needed_libraries"],
    }


def _parse_elf_symbols(data: bytes, endian: str, is_64: bool, sections: list[dict]) -> list[dict]:
    symbols = []
    for section in sections:
        if section.get("type_name") not in {"symtab", "dynsym"}:
            continue
        link = section.get("link")
        if not isinstance(link, int) or link < 0 or link >= len(sections):
            continue
        strings = _slice(data, sections[link].get("offset", 0), sections[link].get("size", 0))
        entry_size = section.get("entry_size") or (24 if is_64 else 16)
        total = min(section.get("size", 0) // entry_size, MAX_SYMBOLS - len(symbols))
        for index in range(total):
            offset = section.get("offset", 0) + index * entry_size
            if offset + entry_size > len(data):
                break
            if is_64:
                name_off, info, other, shndx, value, size = struct.unpack_from(
                    f"{endian}IBBHQQ", data, offset
                )
            else:
                name_off, value, size, info, other, shndx = struct.unpack_from(
                    f"{endian}IIIBBH", data, offset
                )
            name = _read_c_string(strings, name_off) if strings else ""
            symbols.append(
                {
                    "table": section.get("name", ""),
                    "index": index,
                    "name": name,
                    "binding": ELF_SYMBOL_BINDINGS.get(info >> 4, f"0x{info >> 4:x}"),
                    "kind": ELF_SYMBOL_TYPES.get(info & 0x0F, f"0x{info & 0x0f:x}"),
                    "visibility": other & 0x03,
                    "section_index": shndx,
                    "undefined": shndx == 0,
                    "value": value,
                    "size": size,
                }
            )
            if len(symbols) >= MAX_SYMBOLS:
                return symbols
    return symbols


def _parse_elf_dynamic(data: bytes, endian: str, is_64: bool, sections: list[dict]) -> dict:
    needed = []
    for section in sections:
        if section.get("type_name") != "dynamic":
            continue
        link = section.get("link")
        strings = b""
        if isinstance(link, int) and 0 <= link < len(sections):
            strings = _slice(data, sections[link].get("offset", 0), sections[link].get("size", 0))
        entry_size = section.get("entry_size") or (16 if is_64 else 8)
        total = min(section.get("size", 0) // entry_size, MAX_SYMBOLS)
        for index in range(total):
            offset = section.get("offset", 0) + index * entry_size
            if offset + entry_size > len(data):
                break
            tag, value = (
                struct.unpack_from(f"{endian}qQ", data, offset)
                if is_64
                else struct.unpack_from(f"{endian}iI", data, offset)
            )
            if tag == 1 and strings:
                name = _read_c_string(strings, value)
                if name:
                    needed.append(name)
            if ELF_DYNAMIC_TAGS.get(tag) == "null":
                break
    return {"needed_libraries": needed}


def _inspect_macho(data: bytes) -> dict:
    if len(data) < 8:
        raise AnalysisError("Mach-O file is too small")
    magic_le = _u32(data, 0)
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_le in {0xFEEDFACE, 0xFEEDFACF}:
        return _inspect_macho_thin(data, "<", magic_le == 0xFEEDFACF)
    if magic_be in {0xFEEDFACE, 0xFEEDFACF}:
        return _inspect_macho_thin(data, ">", magic_be == 0xFEEDFACF)
    return {}


def _inspect_macho_thin(data: bytes, endian: str, is_64: bool) -> dict:
    header_size = 32 if is_64 else 28
    if len(data) < header_size:
        raise AnalysisError("Mach-O header is incomplete")
    command_count = struct.unpack_from(f"{endian}I", data, 16)[0]
    cursor = header_size
    symtab = {}
    for _ in range(min(command_count, MAX_SYMBOLS)):
        if cursor + 8 > len(data):
            break
        command, size = struct.unpack_from(f"{endian}II", data, cursor)
        if size < 8 or cursor + size > len(data):
            break
        if (command & 0x7FFFFFFF) == 0x2 and size >= 24:
            symoff, nsyms, stroff, strsize = struct.unpack_from(f"{endian}IIII", data, cursor + 8)
            symtab = {"symoff": symoff, "nsyms": nsyms, "stroff": stroff, "strsize": strsize}
            break
        cursor += size
    symbols = _parse_macho_symbols(data, endian, is_64, symtab)
    return {
        "symbols": symbols,
        "imports": _undefined_symbols(symbols),
        "exports": _defined_exports(symbols),
    }


def _parse_macho_symbols(data: bytes, endian: str, is_64: bool, symtab: dict) -> list[dict]:
    if not symtab:
        return []
    strings = _slice(data, symtab.get("stroff", 0), symtab.get("strsize", 0))
    entry_size = 16 if is_64 else 12
    symbols = []
    for index in range(min(symtab.get("nsyms", 0), MAX_SYMBOLS)):
        offset = symtab.get("symoff", 0) + index * entry_size
        if offset + entry_size > len(data):
            break
        if is_64:
            name_off, raw_type, section, desc, value = struct.unpack_from(
                f"{endian}IBBHQ", data, offset
            )
        else:
            name_off, raw_type, section, desc, value = struct.unpack_from(
                f"{endian}IBBHI", data, offset
            )
        base_type = raw_type & 0x0E
        symbols.append(
            {
                "index": index,
                "name": _read_c_string(strings, name_off) if strings else "",
                "kind": _macho_symbol_type(base_type),
                "binding": "external" if raw_type & 0x01 else "local",
                "section": section,
                "undefined": base_type == 0,
                "value": value,
                "size": "",
            }
        )
    return symbols


def _undefined_symbols(symbols: list[dict]) -> list[dict]:
    return [
        item
        for item in symbols
        if item.get("undefined") and item.get("name") and item.get("binding") != "local"
    ]


def _defined_exports(symbols: list[dict]) -> list[dict]:
    return [
        item
        for item in symbols
        if not item.get("undefined") and item.get("name") and item.get("binding") != "local"
    ]


def _macho_symbol_type(value: int) -> str:
    return {
        0x0: "undefined",
        0x2: "absolute",
        0xA: "indirect",
        0xC: "prebound_undefined",
        0xE: "section",
    }.get(value, f"0x{value:x}")


def _coff_name(data: bytes, raw_name: bytes, string_table: int, string_table_size: int) -> str:
    zeroes, string_offset = struct.unpack_from("<II", raw_name, 0)
    if zeroes == 0 and string_offset > 0 and string_table_size > 4:
        absolute = string_table + string_offset
        end = string_table + string_table_size
        if string_table + 4 <= absolute < min(end, len(data)):
            return _read_c_string(data, absolute, min(4096, end - absolute))
    return raw_name.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _rva_to_offset(sections: list[dict], rva: int) -> int | None:
    for section in sections:
        start = section.get("virtual_address", 0)
        size = max(section.get("virtual_size", 0), section.get("raw_size", 0))
        if start <= rva < start + size:
            return section.get("raw_offset", 0) + (rva - start)
    return rva if rva < 0x1000 else None


def _slice(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset > len(data):
        return b""
    return data[offset : min(offset + size, len(data))]


def _read_c_string(data: bytes, offset: int | None, limit: int = 4096) -> str:
    if offset is None or offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(offset + limit, len(data)))
    if end < 0:
        end = min(offset + limit, len(data))
    return data[offset:end].decode("utf-8", errors="replace")


def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise AnalysisError("field extends past end of data")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise AnalysisError("field extends past end of data")
    return struct.unpack_from("<I", data, offset)[0]


def dumps(payload: dict) -> str:
    """Render stable JSON for CLI output."""
    return json.dumps(payload, indent=2) + "\n"
