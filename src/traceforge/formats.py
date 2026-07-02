"""Offline format parsers used by TraceForge."""

from __future__ import annotations

import io
import re
import struct
import zipfile
from pathlib import Path

from traceforge.core_types import AnalysisError

MAX_IMPORTS = 512
MAX_EXPORTS = 512
MAX_SECTIONS = 512
MAX_CONTAINER_ENTRIES = 512
MAX_EMBEDDED_ARTIFACTS = 128

PE_MACHINES = {
    0x014C: "i386",
    0x0200: "ia64",
    0x8664: "amd64",
    0x01C0: "arm",
    0x01C4: "armv7",
    0xAA64: "arm64",
}

PE_SUBSYSTEMS = {
    1: "native",
    2: "windows_gui",
    3: "windows_console",
    9: "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
}

PE_DIRECTORIES = (
    "export", "import", "resource", "exception", "certificate", "base_relocation",
    "debug", "architecture", "global_ptr", "tls", "load_config", "bound_import",
    "iat", "delay_import", "clr_runtime", "reserved",
)

ELF_MACHINES = {
    0x03: "x86",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "aarch64",
    0xF3: "riscv",
}

MACHO_CPU_TYPES = {
    7: "x86",
    12: "arm",
    0x01000007: "x86_64",
    0x0100000C: "arm64",
}

WASM_SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data_count",
}


def analyze_format(data: bytes, filename: str = "") -> dict:
    """Return structured metadata for the recognized file format."""
    kind = identify_kind(data, filename)
    result = {
        "kind": kind,
        "extension": Path(filename).suffix.lower(),
        "confidence": "high" if kind != "raw" else "low",
        "details": {},
        "embedded": find_embedded_artifacts(data),
    }
    try:
        if kind == "pe":
            result["details"] = parse_pe(data)
        elif kind == "elf":
            result["details"] = parse_elf(data)
        elif kind == "macho":
            result["details"] = parse_macho(data)
        elif kind in {"zip", "apk", "jar"}:
            result["details"] = parse_zip_container(data, filename)
        elif kind == "wasm":
            result["details"] = parse_wasm(data)
    except AnalysisError as exc:
        result["error"] = str(exc)
    return result


def identify_kind(data: bytes, filename: str = "") -> str:
    suffix = Path(filename).suffix.lower()
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(
        (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    ):
        return "macho"
    if data.startswith((b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")):
        return "macho"
    if data.startswith(b"\x00asm"):
        return "wasm"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        if suffix == ".apk":
            return "apk"
        if suffix in {".jar", ".war", ".ear"}:
            return "jar"
        return "zip"
    return "raw"


def find_embedded_artifacts(data: bytes) -> list[dict]:
    signatures = (
        (b"MZ", "pe"),
        (b"\x7fELF", "elf"),
        (b"\x00asm", "wasm"),
        (b"PK\x03\x04", "zip"),
        (b"\xfe\xed\xfa\xcf", "macho"),
        (b"\xcf\xfa\xed\xfe", "macho"),
        (b"\xfe\xed\xfa\xce", "macho"),
        (b"\xce\xfa\xed\xfe", "macho"),
    )
    hits = {}
    for magic, kind in signatures:
        start = 1
        while True:
            offset = data.find(magic, start)
            if offset < 0:
                break
            hits[(offset, kind)] = {"offset": offset, "kind": kind, "magic": magic.hex()}
            start = offset + 1
            if len(hits) >= MAX_EMBEDDED_ARTIFACTS:
                break
        if len(hits) >= MAX_EMBEDDED_ARTIFACTS:
            break
    return [hits[key] for key in sorted(hits)][:MAX_EMBEDDED_ARTIFACTS]


def parse_pe(data: bytes) -> dict:
    if len(data) < 0x40:
        raise AnalysisError("PE file is too small for DOS header")
    e_lfanew = _u32(data, 0x3C, "<")
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise AnalysisError("PE signature not found at DOS e_lfanew")

    coff = e_lfanew + 4
    machine = _u16(data, coff, "<")
    section_count = _u16(data, coff + 2, "<")
    timestamp = _u32(data, coff + 4, "<")
    optional_size = _u16(data, coff + 16, "<")
    characteristics = _u16(data, coff + 18, "<")
    opt = coff + 20
    if opt + optional_size > len(data):
        raise AnalysisError("PE optional header extends past end of file")
    magic = _u16(data, opt, "<")
    is_pe64 = magic == 0x20B
    if magic not in {0x10B, 0x20B}:
        raise AnalysisError(f"unsupported PE optional header magic 0x{magic:x}")

    entry_rva = _u32(data, opt + 16, "<")
    image_base = _u64(data, opt + 24, "<") if is_pe64 else _u32(data, opt + 28, "<")
    size_of_image = _u32(data, opt + 56, "<")
    size_of_headers = _u32(data, opt + 60, "<")
    subsystem = _u16(data, opt + 68, "<")
    dll_characteristics = _u16(data, opt + 70, "<")
    directory_offset = opt + (112 if is_pe64 else 96)
    directories = _parse_pe_directories(data, directory_offset, optional_size - (directory_offset - opt))
    sections = _parse_pe_sections(data, opt + optional_size, section_count)
    entry_section = _section_for_rva(sections, entry_rva)
    imports = _parse_pe_imports(data, sections, directories.get("import"), is_pe64)
    exports = _parse_pe_exports(data, sections, directories.get("export"))
    observations = _pe_observations(sections, entry_section, imports, directories)
    return {
        "format": "pe32+" if is_pe64 else "pe32",
        "machine": PE_MACHINES.get(machine, f"0x{machine:04x}"),
        "section_count": section_count,
        "timestamp": timestamp,
        "characteristics": f"0x{characteristics:04x}",
        "image_base": image_base,
        "entry_point_rva": entry_rva,
        "entry_section": entry_section["name"] if entry_section else None,
        "size_of_image": size_of_image,
        "size_of_headers": size_of_headers,
        "subsystem": PE_SUBSYSTEMS.get(subsystem, f"0x{subsystem:04x}"),
        "dll_characteristics": f"0x{dll_characteristics:04x}",
        "directories": directories,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "observations": observations,
    }


def parse_elf(data: bytes) -> dict:
    if len(data) < 0x34 or not data.startswith(b"\x7fELF"):
        raise AnalysisError("ELF header not found")
    elf_class = data[4]
    endian_flag = data[5]
    if elf_class not in {1, 2} or endian_flag not in {1, 2}:
        raise AnalysisError("unsupported ELF class or endian value")
    endian = "<" if endian_flag == 1 else ">"
    is_64 = elf_class == 2
    if is_64:
        fields = _unpack_from(f"{endian}HHIQQQIHHHHHH", data, 16)
        e_type, e_machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = fields
    else:
        fields = _unpack_from(f"{endian}HHIIIIIHHHHHH", data, 16)
        e_type, e_machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = fields
    sections = _parse_elf_sections(data, endian, is_64, shoff, shentsize, shnum, shstrndx)
    return {
        "class": "elf64" if is_64 else "elf32",
        "endian": "little" if endian == "<" else "big",
        "type": e_type,
        "machine": ELF_MACHINES.get(e_machine, f"0x{e_machine:x}"),
        "version": version,
        "entry": entry,
        "program_header_offset": phoff,
        "program_header_count": phnum,
        "section_header_offset": shoff,
        "section_count": shnum,
        "flags": f"0x{flags:x}",
        "header_size": ehsize,
        "sections": sections,
        "needed_libraries": [],
        "imports": [],
        "exports": [],
    }


def parse_macho(data: bytes) -> dict:
    if len(data) < 8:
        raise AnalysisError("Mach-O file is too small")
    magic_be = _u32(data, 0, ">")
    magic_le = _u32(data, 0, "<")
    if magic_be == 0xCAFEBABE or magic_le == 0xCAFEBABE:
        endian = ">" if magic_be == 0xCAFEBABE else "<"
        count = _u32(data, 4, endian)
        return {"format": "fat", "architecture_count": count, "architectures": []}
    if magic_le in {0xFEEDFACE, 0xFEEDFACF}:
        return _parse_macho_thin(data, "<", magic_le == 0xFEEDFACF)
    if magic_be in {0xFEEDFACE, 0xFEEDFACF}:
        return _parse_macho_thin(data, ">", magic_be == 0xFEEDFACF)
    raise AnalysisError("Mach-O magic not recognized")


def parse_zip_container(data: bytes, filename: str = "") -> dict:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise AnalysisError(f"invalid zip container: {exc}") from exc

    entries = []
    permissions = set()
    manifest_text = ""
    class_count = 0
    dex_count = 0
    native_libs = 0
    all_infos = archive.infolist()
    with archive:
        for info in all_infos[:MAX_CONTAINER_ENTRIES]:
            name = info.filename
            class_count += int(name.endswith(".class"))
            dex_count += int(name.endswith(".dex"))
            native_libs += int(name.startswith("lib/") and name.endswith(".so"))
            entries.append(
                {
                    "name": name,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "crc32": f"{info.CRC:08x}",
                    "is_dir": info.is_dir(),
                }
            )
            if name in {"META-INF/MANIFEST.MF", "AndroidManifest.xml"}:
                raw = archive.read(info)[:65536]
                manifest_text = raw.decode("utf-8", errors="ignore")
                permissions.update(re.findall(r"android\.permission\.[A-Z0-9_]+", manifest_text))

    names = {entry["name"] for entry in entries}
    suffix = Path(filename).suffix.lower()
    kind = "zip"
    if suffix == ".apk" or {"AndroidManifest.xml", "classes.dex"} <= names:
        kind = "apk"
    elif suffix in {".jar", ".war", ".ear"} or "META-INF/MANIFEST.MF" in names:
        kind = "jar"
    return {
        "container_kind": kind,
        "entry_count": len(all_infos),
        "entries_truncated": len(all_infos) > len(entries),
        "entries": entries,
        "apk": {
            "dex_count": dex_count,
            "native_library_count": native_libs,
            "permissions": sorted(permissions),
        },
        "jar": {
            "class_count": class_count,
            "manifest_present": "META-INF/MANIFEST.MF" in names,
            "manifest_preview": manifest_text[:2000] if manifest_text else "",
        },
    }


def parse_wasm(data: bytes) -> dict:
    if len(data) < 8 or data[:4] != b"\x00asm":
        raise AnalysisError("WASM magic not found")
    version = _u32(data, 4, "<")
    offset = 8
    sections = []
    imports = []
    exports = []
    while offset < len(data):
        section_id = data[offset]
        offset += 1
        size, offset = _read_varuint(data, offset)
        payload_start = offset
        payload_end = offset + size
        if payload_end > len(data):
            raise AnalysisError("WASM section extends past end of file")
        payload = data[payload_start:payload_end]
        section = {
            "id": section_id,
            "name": WASM_SECTION_NAMES.get(section_id, f"section_{section_id}"),
            "offset": payload_start,
            "size": size,
        }
        if section_id == 2:
            imports = _parse_wasm_imports(payload)
            section["count"] = len(imports)
        elif section_id == 7:
            exports = _parse_wasm_exports(payload)
            section["count"] = len(exports)
        sections.append(section)
        offset = payload_end
    return {"version": version, "sections": sections, "imports": imports, "exports": exports}


def _parse_pe_directories(data: bytes, offset: int, available: int) -> dict:
    count = min(len(PE_DIRECTORIES), max(available, 0) // 8)
    directories = {}
    for index in range(count):
        rva = _u32(data, offset + index * 8, "<")
        size = _u32(data, offset + index * 8 + 4, "<")
        if rva or size:
            directories[PE_DIRECTORIES[index]] = {"rva": rva, "size": size}
    return directories


def _parse_pe_sections(data: bytes, offset: int, count: int) -> list[dict]:
    sections = []
    for index in range(min(count, MAX_SECTIONS)):
        item = offset + index * 40
        if item + 40 > len(data):
            break
        name = data[item : item + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        virtual_size = _u32(data, item + 8, "<")
        virtual_address = _u32(data, item + 12, "<")
        raw_size = _u32(data, item + 16, "<")
        raw_offset = _u32(data, item + 20, "<")
        characteristics = _u32(data, item + 36, "<")
        sections.append(
            {
                "index": index,
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "characteristics": f"0x{characteristics:08x}",
                "readable": bool(characteristics & 0x40000000),
                "writable": bool(characteristics & 0x80000000),
                "executable": bool(characteristics & 0x20000000),
            }
        )
    return sections


def _parse_pe_imports(data: bytes, sections: list[dict], directory: dict | None, is_pe64: bool) -> list[dict]:
    if not directory or not directory.get("rva"):
        return []
    offset = _rva_to_offset(sections, directory["rva"])
    if offset is None:
        return []
    imports = []
    thunk_size = 8 if is_pe64 else 4
    for index in range(MAX_IMPORTS):
        descriptor = offset + index * 20
        if descriptor + 20 > len(data):
            break
        original_thunk, _timestamp, _forwarder, name_rva, first_thunk = struct.unpack_from(
            "<IIIII", data, descriptor
        )
        if not any((original_thunk, name_rva, first_thunk)):
            break
        dll_name = _read_pe_string(data, sections, name_rva) or f"dll_{index}"
        symbols = []
        thunk_offset = _rva_to_offset(sections, original_thunk or first_thunk)
        if thunk_offset is not None:
            for thunk_index in range(MAX_IMPORTS):
                item = thunk_offset + thunk_index * thunk_size
                if item + thunk_size > len(data):
                    break
                thunk_value = _u64(data, item, "<") if is_pe64 else _u32(data, item, "<")
                if thunk_value == 0:
                    break
                name_offset = _rva_to_offset(sections, thunk_value & 0x7FFFFFFFFFFFFFFF)
                if name_offset is None or name_offset + 2 >= len(data):
                    continue
                name = _read_c_string(data, name_offset + 2)
                if name:
                    symbols.append({"name": name})
        imports.append({"library": dll_name, "symbols": symbols})
    return imports


def _parse_pe_exports(data: bytes, sections: list[dict], directory: dict | None) -> list[dict]:
    if not directory or not directory.get("rva"):
        return []
    offset = _rva_to_offset(sections, directory["rva"])
    if offset is None or offset + 40 > len(data):
        return []
    fields = struct.unpack_from("<IIHHIIIIIII", data, offset)
    name_rva, ordinal_base, name_count, names_rva, ordinals_rva = fields[4], fields[5], fields[7], fields[9], fields[10]
    module_name = _read_pe_string(data, sections, name_rva) or ""
    names_offset = _rva_to_offset(sections, names_rva)
    ordinals_offset = _rva_to_offset(sections, ordinals_rva)
    if names_offset is None or ordinals_offset is None:
        return []
    exports = []
    for index in range(min(name_count, MAX_EXPORTS)):
        name_ptr = names_offset + index * 4
        ordinal_ptr = ordinals_offset + index * 2
        if name_ptr + 4 > len(data) or ordinal_ptr + 2 > len(data):
            break
        name = _read_pe_string(data, sections, _u32(data, name_ptr, "<"))
        if name:
            exports.append({"name": name, "ordinal": ordinal_base + _u16(data, ordinal_ptr, "<"), "module": module_name})
    return exports


def _pe_observations(sections: list[dict], entry_section: dict | None, imports: list[dict], directories: dict) -> list[dict]:
    observations = []
    for section in sections:
        if section["executable"] and section["writable"]:
            observations.append(
                {
                    "id": "pe_writable_executable_section",
                    "detail": f"section {section['name']} is both writable and executable",
                    "evidence": section["name"],
                }
            )
        if section["raw_size"] == 0 and section["virtual_size"] > 0:
            observations.append(
                {
                    "id": "pe_virtual_only_section",
                    "detail": f"section {section['name']} has virtual size but no raw bytes",
                    "evidence": section["name"],
                }
            )
    if entry_section is not None and not entry_section["executable"]:
        observations.append(
            {
                "id": "pe_entry_in_non_executable_section",
                "detail": "entry point maps to a non-executable section",
                "evidence": entry_section["name"],
            }
        )
    if sum(len(item["symbols"]) for item in imports) == 0 and directories.get("import"):
        observations.append(
            {
                "id": "pe_import_directory_unparsed",
                "detail": "import directory exists but no import names were resolved",
                "evidence": "import",
            }
        )
    return observations


def _parse_elf_sections(data: bytes, endian: str, is_64: bool, offset: int, entry_size: int, count: int, names_index: int) -> list[dict]:
    if offset <= 0 or entry_size <= 0:
        return []
    raw = []
    for index in range(min(count, MAX_SECTIONS)):
        item = offset + index * entry_size
        if item + entry_size > len(data):
            break
        if is_64:
            fields = _unpack_from(f"{endian}IIQQQQIIQQ", data, item)
            name_off, sec_type, flags, addr, sec_offset, size, link, info, _align, entsize = fields
        else:
            fields = _unpack_from(f"{endian}IIIIIIIIII", data, item)
            name_off, sec_type, flags, addr, sec_offset, size, link, info, _align, entsize = fields
        raw.append({"index": index, "name_offset": name_off, "type": sec_type, "flags": flags, "address": addr, "offset": sec_offset, "size": size, "link": link, "info": info, "entry_size": entsize})
    names = b""
    if 0 <= names_index < len(raw):
        names = _slice(data, raw[names_index]["offset"], raw[names_index]["size"])
    return [
        {
            "index": section["index"],
            "name": _read_c_string(names, section["name_offset"]) if names else "",
            "type": f"0x{section['type']:x}",
            "flags": f"0x{section['flags']:x}",
            "address": section["address"],
            "offset": section["offset"],
            "size": section["size"],
            "link": section["link"],
            "info": section["info"],
            "entry_size": section["entry_size"],
        }
        for section in raw
    ]


def _parse_macho_thin(data: bytes, endian: str, is_64: bool) -> dict:
    header_size = 32 if is_64 else 28
    if len(data) < header_size:
        raise AnalysisError("Mach-O header is incomplete")
    cpu_type, cpu_subtype, file_type, command_count, command_size, flags = struct.unpack_from(
        f"{endian}IIIIII", data, 4
    )
    return {
        "format": "macho64" if is_64 else "macho32",
        "endian": "little" if endian == "<" else "big",
        "cpu": MACHO_CPU_TYPES.get(cpu_type, f"0x{cpu_type:x}"),
        "cpu_subtype": cpu_subtype,
        "file_type": file_type,
        "flags": f"0x{flags:x}",
        "load_command_count": command_count,
        "load_command_size": command_size,
        "load_commands": [],
        "linked_libraries": [],
        "segments": [],
    }


def _parse_wasm_imports(payload: bytes) -> list[dict]:
    imports = []
    try:
        count, offset = _read_varuint(payload, 0)
        for _ in range(min(count, MAX_IMPORTS)):
            module, offset = _read_wasm_name(payload, offset)
            name, offset = _read_wasm_name(payload, offset)
            kind = payload[offset]
            offset += 1
            if kind == 0:
                _, offset = _read_varuint(payload, offset)
            imports.append({"module": module, "name": name, "kind": kind})
    except (IndexError, AnalysisError):
        return imports
    return imports


def _parse_wasm_exports(payload: bytes) -> list[dict]:
    exports = []
    try:
        count, offset = _read_varuint(payload, 0)
        for _ in range(min(count, MAX_EXPORTS)):
            name, offset = _read_wasm_name(payload, offset)
            kind = payload[offset]
            offset += 1
            index, offset = _read_varuint(payload, offset)
            exports.append({"name": name, "kind": kind, "index": index})
    except (IndexError, AnalysisError):
        return exports
    return exports


def _read_wasm_name(data: bytes, offset: int) -> tuple[str, int]:
    size, offset = _read_varuint(data, offset)
    end = offset + size
    if end > len(data):
        raise AnalysisError("WASM name extends past section")
    return data[offset:end].decode("utf-8", errors="replace"), end


def _read_varuint(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    for _ in range(5):
        if offset >= len(data):
            raise AnalysisError("varuint extends past end of data")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
    raise AnalysisError("varuint is too long")


def _rva_to_offset(sections: list[dict], rva: int) -> int | None:
    for section in sections:
        start = section["virtual_address"]
        size = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + size:
            return section["raw_offset"] + (rva - start)
    return rva if rva < 0x1000 else None


def _section_for_rva(sections: list[dict], rva: int) -> dict | None:
    for section in sections:
        start = section["virtual_address"]
        size = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + size:
            return section
    return None


def _read_pe_string(data: bytes, sections: list[dict], rva: int) -> str:
    offset = _rva_to_offset(sections, rva)
    return _read_c_string(data, offset) if offset is not None else ""


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


def _u16(data: bytes, offset: int, endian: str) -> int:
    return _unpack_from(f"{endian}H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str) -> int:
    return _unpack_from(f"{endian}I", data, offset)[0]


def _u64(data: bytes, offset: int, endian: str) -> int:
    return _unpack_from(f"{endian}Q", data, offset)[0]


def _unpack_from(fmt: str, data: bytes, offset: int) -> tuple:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise AnalysisError("structured field extends past end of data")
    return struct.unpack_from(fmt, data, offset)
