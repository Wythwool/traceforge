"""Static executable code mapping for local file bytes."""

from __future__ import annotations

import csv
import json
import struct
from pathlib import Path

from traceforge.formats import analyze_format

MAX_CODE_RANGES = 128
MAX_FUNCTIONS = 256
MAX_INSTRUCTIONS = 512
MAX_INSTRUCTIONS_PER_RANGE = 96
MAX_RANGE_BYTES = 4096

X86_REGS_32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
X86_REGS_64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi")
X86_CONDITIONS = {
    0x70: "jo",
    0x71: "jno",
    0x72: "jb",
    0x73: "jae",
    0x74: "je",
    0x75: "jne",
    0x76: "jbe",
    0x77: "ja",
    0x78: "js",
    0x79: "jns",
    0x7A: "jp",
    0x7B: "jnp",
    0x7C: "jl",
    0x7D: "jge",
    0x7E: "jle",
    0x7F: "jg",
}
X86_NEAR_CONDITIONS = {
    0x80: "jo",
    0x81: "jno",
    0x82: "jb",
    0x83: "jae",
    0x84: "je",
    0x85: "jne",
    0x86: "jbe",
    0x87: "ja",
    0x88: "js",
    0x89: "jns",
    0x8A: "jp",
    0x8B: "jnp",
    0x8C: "jl",
    0x8D: "jge",
    0x8E: "jle",
    0x8F: "jg",
}


def inspect_code_file(path: Path) -> dict:
    """Inspect executable byte ranges and a bounded instruction preview."""
    path = Path(path)
    return inspect_code(path.read_bytes(), path.name)


def inspect_code(
    data: bytes,
    filename: str = "",
    format_info: dict | None = None,
    symbol_info: dict | None = None,
) -> dict:
    """Return a static code map for executable regions visible in the file."""
    format_info = format_info if format_info is not None else analyze_format(data, filename)
    symbol_info = symbol_info or {}
    architecture = _architecture(format_info)
    ranges = _code_ranges(format_info)
    instructions, edges = _decode_ranges(data, ranges, architecture)
    functions = _function_candidates(format_info, symbol_info, ranges, instructions)
    return {
        "file_name": filename,
        "format": format_info.get("kind", "raw"),
        "architecture": architecture,
        "entry_point": _entry_point(format_info, ranges),
        "ranges": ranges,
        "functions": functions,
        "instructions": instructions,
        "edges": edges,
        "truncated": {
            "ranges": len(ranges) >= MAX_CODE_RANGES,
            "instructions": len(instructions) >= MAX_INSTRUCTIONS,
            "functions": len(functions) >= MAX_FUNCTIONS,
        },
    }


def write_code_csv(path: Path, payload: dict) -> Path:
    """Write instruction preview rows for spreadsheet review."""
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["range", "offset", "address", "size", "mnemonic", "operands", "bytes"])
        for item in payload.get("instructions", []):
            writer.writerow(
                [
                    item.get("range", ""),
                    item.get("offset", ""),
                    _hex_or_empty(item.get("address")),
                    item.get("size", ""),
                    item.get("mnemonic", ""),
                    item.get("operands", ""),
                    item.get("bytes", ""),
                ]
            )
    return Path(path)


def dumps(payload: dict) -> str:
    """Render stable JSON for CLI output."""
    return json.dumps(payload, indent=2) + "\n"


def _architecture(format_info: dict) -> str:
    details = format_info.get("details", {})
    kind = format_info.get("kind", "raw")
    if kind == "pe":
        machine = str(details.get("machine", "")).lower()
        if machine == "amd64":
            return "x86_64"
        if machine == "i386":
            return "x86"
        if machine == "arm64":
            return "arm64"
        if machine.startswith("arm"):
            return "arm"
    if kind == "elf":
        machine = str(details.get("machine", "")).lower()
        if machine in {"x86_64", "x86"}:
            return machine
        if machine in {"aarch64", "arm64"}:
            return "arm64"
        if machine == "arm":
            return "arm"
    if kind == "macho":
        cpu = str(details.get("cpu", "")).lower()
        if cpu in {"x86_64", "x86", "arm64", "arm"}:
            return cpu
    if kind == "wasm":
        return "wasm"
    return "unknown"


def _code_ranges(format_info: dict) -> list[dict]:
    kind = format_info.get("kind", "raw")
    details = format_info.get("details", {})
    if kind == "pe":
        return _pe_code_ranges(details)
    if kind == "elf":
        return _elf_code_ranges(details)
    if kind == "macho":
        return _macho_code_ranges(details)
    if kind == "wasm":
        return _wasm_code_ranges(details)
    return []


def _pe_code_ranges(details: dict) -> list[dict]:
    image_base = details.get("image_base", 0)
    ranges = []
    for section in details.get("sections", []):
        if not section.get("executable"):
            continue
        raw_size = section.get("raw_size", 0)
        raw_offset = section.get("raw_offset", 0)
        if raw_size <= 0:
            continue
        virtual_address = section.get("virtual_address", 0)
        ranges.append(
            _range(
                name=section.get("name", f"section_{len(ranges)}"),
                kind="section",
                offset=raw_offset,
                size=raw_size,
                virtual_address=image_base + virtual_address,
                permissions=section.get("permissions", "r-x"),
            )
        )
    return ranges[:MAX_CODE_RANGES]


def _elf_code_ranges(details: dict) -> list[dict]:
    ranges = []
    for section in details.get("sections", []):
        permissions = section.get("permissions", "")
        if "x" not in permissions and "execute" not in section.get("flag_names", []):
            continue
        size = section.get("size", 0)
        if size <= 0:
            continue
        ranges.append(
            _range(
                name=section.get("name", f"section_{len(ranges)}"),
                kind="section",
                offset=section.get("offset", 0),
                size=size,
                virtual_address=section.get("address", 0),
                permissions=permissions or "--x",
            )
        )
    if ranges:
        return ranges[:MAX_CODE_RANGES]

    for header in details.get("program_headers", []):
        permissions = header.get("permissions", "")
        if "x" not in permissions:
            continue
        size = header.get("file_size", 0)
        if size <= 0:
            continue
        ranges.append(
            _range(
                name=f"program_header_{header.get('index', len(ranges))}",
                kind="segment",
                offset=header.get("offset", 0),
                size=size,
                virtual_address=header.get("virtual_address", 0),
                permissions=permissions,
            )
        )
    return ranges[:MAX_CODE_RANGES]


def _macho_code_ranges(details: dict) -> list[dict]:
    execute_segments = {
        segment.get("name", "")
        for segment in details.get("segments", [])
        if "execute" in segment.get("initial_protection", [])
    }
    ranges = []
    for section in details.get("sections", []):
        segment = section.get("segment", "")
        if execute_segments and segment not in execute_segments:
            continue
        size = section.get("size", 0)
        if size <= 0:
            continue
        ranges.append(
            _range(
                name=section.get("name", f"section_{len(ranges)}"),
                kind="section",
                offset=section.get("offset", 0),
                size=size,
                virtual_address=section.get("address", 0),
                permissions="r-x",
            )
        )
    if ranges:
        return ranges[:MAX_CODE_RANGES]
    for segment in details.get("segments", []):
        if "execute" not in segment.get("initial_protection", []):
            continue
        size = segment.get("filesize", 0)
        if size <= 0:
            continue
        ranges.append(
            _range(
                name=segment.get("name", f"segment_{len(ranges)}"),
                kind="segment",
                offset=segment.get("fileoff", 0),
                size=size,
                virtual_address=segment.get("virtual_address", 0),
                permissions="r-x",
            )
        )
    return ranges[:MAX_CODE_RANGES]


def _wasm_code_ranges(details: dict) -> list[dict]:
    ranges = []
    for section in details.get("sections", []):
        if section.get("name") != "code":
            continue
        ranges.append(
            _range(
                name="code",
                kind="wasm_section",
                offset=section.get("offset", 0),
                size=section.get("size", 0),
                virtual_address=section.get("offset", 0),
                permissions="--x",
            )
        )
    return ranges[:MAX_CODE_RANGES]


def _range(
    name: str,
    kind: str,
    offset: int,
    size: int,
    virtual_address: int,
    permissions: str,
) -> dict:
    capped_size = min(size, MAX_RANGE_BYTES)
    return {
        "name": name,
        "kind": kind,
        "offset": offset,
        "size": size,
        "mapped_size": capped_size,
        "virtual_address": virtual_address,
        "permissions": permissions,
    }


def _decode_ranges(
    data: bytes, ranges: list[dict], architecture: str
) -> tuple[list[dict], list[dict]]:
    instructions = []
    edges = []
    for item in ranges:
        offset = item["offset"]
        limit = min(offset + item["mapped_size"], len(data))
        count = 0
        while offset < limit and len(instructions) < MAX_INSTRUCTIONS:
            decoded = _decode_instruction(data, offset, item, architecture)
            instructions.append(decoded)
            if decoded.get("target") is not None:
                edges.append(
                    {
                        "source": decoded["address"],
                        "target": decoded["target"],
                        "kind": "call" if decoded["mnemonic"] == "call" else "branch",
                        "source_offset": decoded["offset"],
                        "range": item["name"],
                    }
                )
            offset += max(decoded["size"], 1)
            count += 1
            if count >= MAX_INSTRUCTIONS_PER_RANGE:
                break
    return instructions, edges


def _decode_instruction(data: bytes, offset: int, code_range: dict, architecture: str) -> dict:
    address = code_range["virtual_address"] + (offset - code_range["offset"])
    if architecture in {"x86", "x86_64"}:
        return _decode_x86(data, offset, address, code_range["name"], architecture == "x86_64")
    if architecture == "arm64":
        return _decode_arm64(data, offset, address, code_range["name"])
    if architecture == "wasm":
        return _instruction(
            code_range["name"], offset, address, 1, "wasm.byte", "", data[offset:offset + 1]
        )
    return _instruction(
        code_range["name"],
        offset,
        address,
        1,
        "db",
        f"0x{data[offset]:02x}",
        data[offset:offset + 1],
    )


def _decode_x86(data: bytes, offset: int, address: int, name: str, is_64: bool) -> dict:
    byte = data[offset]
    regs = X86_REGS_64 if is_64 else X86_REGS_32
    if byte == 0x90:
        return _instruction(name, offset, address, 1, "nop", "", data[offset:offset + 1])
    if byte == 0xC3:
        return _instruction(name, offset, address, 1, "ret", "", data[offset:offset + 1])
    if byte == 0xCC:
        return _instruction(name, offset, address, 1, "int3", "", data[offset:offset + 1])
    if 0x50 <= byte <= 0x57:
        return _instruction(
            name, offset, address, 1, "push", regs[byte - 0x50], data[offset:offset + 1]
        )
    if 0x58 <= byte <= 0x5F:
        return _instruction(
            name, offset, address, 1, "pop", regs[byte - 0x58], data[offset:offset + 1]
        )
    if 0xB8 <= byte <= 0xBF and offset + 5 <= len(data):
        value = struct.unpack_from("<I", data, offset + 1)[0]
        return _instruction(
            name,
            offset,
            address,
            5,
            "mov",
            f"{regs[byte - 0xB8]}, 0x{value:x}",
            data[offset:offset + 5],
        )
    if byte == 0xE8 and offset + 5 <= len(data):
        rel = struct.unpack_from("<i", data, offset + 1)[0]
        target = address + 5 + rel
        return _instruction(
            name,
            offset,
            address,
            5,
            "call",
            f"0x{target:x}",
            data[offset:offset + 5],
            target,
        )
    if byte == 0xE9 and offset + 5 <= len(data):
        rel = struct.unpack_from("<i", data, offset + 1)[0]
        target = address + 5 + rel
        return _instruction(
            name,
            offset,
            address,
            5,
            "jmp",
            f"0x{target:x}",
            data[offset:offset + 5],
            target,
        )
    if byte == 0xEB and offset + 2 <= len(data):
        rel = struct.unpack_from("<b", data, offset + 1)[0]
        target = address + 2 + rel
        return _instruction(
            name,
            offset,
            address,
            2,
            "jmp",
            f"0x{target:x}",
            data[offset:offset + 2],
            target,
        )
    if byte in X86_CONDITIONS and offset + 2 <= len(data):
        rel = struct.unpack_from("<b", data, offset + 1)[0]
        target = address + 2 + rel
        return _instruction(
            name,
            offset,
            address,
            2,
            X86_CONDITIONS[byte],
            f"0x{target:x}",
            data[offset:offset + 2],
            target,
        )
    if byte == 0x0F and offset + 6 <= len(data) and data[offset + 1] in X86_NEAR_CONDITIONS:
        rel = struct.unpack_from("<i", data, offset + 2)[0]
        target = address + 6 + rel
        return _instruction(
            name,
            offset,
            address,
            6,
            X86_NEAR_CONDITIONS[data[offset + 1]],
            f"0x{target:x}",
            data[offset:offset + 6],
            target,
        )
    return _instruction(name, offset, address, 1, "db", f"0x{byte:02x}", data[offset:offset + 1])


def _decode_arm64(data: bytes, offset: int, address: int, name: str) -> dict:
    if offset + 4 > len(data):
        return _instruction(
            name, offset, address, 1, "db", f"0x{data[offset]:02x}", data[offset:offset + 1]
        )
    word = struct.unpack_from("<I", data, offset)[0]
    raw = data[offset:offset + 4]
    if word == 0xD503201F:
        return _instruction(name, offset, address, 4, "nop", "", raw)
    if word == 0xD65F03C0:
        return _instruction(name, offset, address, 4, "ret", "", raw)
    if word & 0xFC000000 == 0x94000000:
        target = address + _sign_extend(word & 0x03FFFFFF, 26) * 4
        return _instruction(name, offset, address, 4, "bl", f"0x{target:x}", raw, target)
    if word & 0xFC000000 == 0x14000000:
        target = address + _sign_extend(word & 0x03FFFFFF, 26) * 4
        return _instruction(name, offset, address, 4, "b", f"0x{target:x}", raw, target)
    return _instruction(name, offset, address, 4, ".word", f"0x{word:08x}", raw)


def _instruction(
    code_range: str,
    offset: int,
    address: int,
    size: int,
    mnemonic: str,
    operands: str,
    raw: bytes,
    target: int | None = None,
) -> dict:
    item = {
        "range": code_range,
        "offset": offset,
        "address": address,
        "size": size,
        "mnemonic": mnemonic,
        "operands": operands,
        "bytes": raw.hex(),
    }
    if target is not None:
        item["target"] = target
    return item


def _function_candidates(
    format_info: dict,
    symbol_info: dict,
    ranges: list[dict],
    instructions: list[dict],
) -> list[dict]:
    candidates = []
    seen = set()
    entry = _entry_point(format_info, ranges)
    if entry.get("address") is not None:
        _add_function(candidates, seen, "entry", entry["address"], entry.get("offset"), "entry")

    for item in symbol_info.get("exports", []) + symbol_info.get("symbols", []):
        name = item.get("name", "")
        value = item.get("value")
        kind = item.get("kind", "")
        if not name or not isinstance(value, int) or kind not in {"function", "0x20", "0x2"}:
            continue
        resolved = _resolve_address(value, ranges)
        if resolved is not None:
            _add_function(candidates, seen, name, resolved["address"], resolved["offset"], "symbol")

    for item in instructions:
        if item.get("mnemonic") not in {"call", "bl"} or item.get("target") is None:
            continue
        resolved = _resolve_address(item["target"], ranges)
        if resolved is not None:
            _add_function(
                candidates,
                seen,
                f"sub_{item['target']:x}",
                resolved["address"],
                resolved["offset"],
                "call_target",
            )
        if len(candidates) >= MAX_FUNCTIONS:
            break
    return candidates[:MAX_FUNCTIONS]


def _entry_point(format_info: dict, ranges: list[dict]) -> dict:
    details = format_info.get("details", {})
    kind = format_info.get("kind", "raw")
    if kind == "pe":
        image_base = details.get("image_base", 0)
        rva = details.get("entry_point_rva")
        if isinstance(rva, int):
            address = image_base + rva
            resolved = _resolve_address(address, ranges)
            return {
                "address": address,
                "offset": resolved["offset"] if resolved else None,
                "section": details.get("entry_section"),
            }
    if kind == "elf":
        address = details.get("entry")
        if isinstance(address, int):
            resolved = _resolve_address(address, ranges)
            return {
                "address": address,
                "offset": resolved["offset"] if resolved else None,
                "section": details.get("entry_section"),
            }
    return {"address": None, "offset": None, "section": None}


def _resolve_address(value: int, ranges: list[dict]) -> dict | None:
    for item in ranges:
        start = item["virtual_address"]
        end = start + item["size"]
        if start <= value < end:
            return {
                "address": value,
                "offset": item["offset"] + (value - start),
                "range": item["name"],
            }
    return None


def _add_function(
    candidates: list[dict],
    seen: set[int],
    name: str,
    address: int,
    offset: int | None,
    source: str,
) -> None:
    if address in seen:
        return
    seen.add(address)
    candidates.append(
        {
            "name": name,
            "address": address,
            "offset": offset,
            "source": source,
        }
    )


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _hex_or_empty(value: int | None) -> str:
    return "" if value is None else f"0x{value:x}"
