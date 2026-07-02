"""Static executable code mapping for local file bytes."""

from __future__ import annotations

import csv
import json
import struct
from pathlib import Path

from traceforge.disasm import decode_with_capstone
from traceforge.formats import analyze_format

DECODERS = {"auto", "builtin", "capstone"}
MAX_CODE_RANGES = 128
MAX_FUNCTIONS = 256
MAX_BASIC_BLOCKS = 512
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
CONDITIONAL_BRANCHES = set(X86_CONDITIONS.values()) | set(X86_NEAR_CONDITIONS.values()) | {
    "b.eq",
    "b.ne",
    "b.cs",
    "b.hs",
    "b.cc",
    "b.lo",
    "b.mi",
    "b.pl",
    "b.vs",
    "b.vc",
    "b.hi",
    "b.ls",
    "b.ge",
    "b.lt",
    "b.gt",
    "b.le",
}
UNCONDITIONAL_BRANCHES = {"jmp", "b", "br"}
RETURN_MNEMONICS = {"ret", "retn", "retf"}


def inspect_code_file(path: Path, decoder: str = "auto") -> dict:
    """Inspect executable byte ranges and a bounded instruction preview."""
    path = Path(path)
    return inspect_code(path.read_bytes(), path.name, decoder=decoder)


def inspect_code(
    data: bytes,
    filename: str = "",
    format_info: dict | None = None,
    symbol_info: dict | None = None,
    decoder: str = "auto",
) -> dict:
    """Return a static code map for executable regions visible in the file."""
    if decoder not in DECODERS:
        raise ValueError(f"unsupported decoder: {decoder}")
    format_info = format_info if format_info is not None else analyze_format(data, filename)
    symbol_info = symbol_info or {}
    architecture = _architecture(format_info)
    ranges = _code_ranges(format_info)
    instructions, edges, decoder_info = _decode_ranges(data, ranges, architecture, decoder)
    functions = _function_candidates(format_info, symbol_info, ranges, instructions)
    basic_blocks = _basic_blocks(ranges, instructions, edges)
    return {
        "file_name": filename,
        "format": format_info.get("kind", "raw"),
        "architecture": architecture,
        "decoder": decoder_info,
        "entry_point": _entry_point(format_info, ranges),
        "ranges": ranges,
        "functions": functions,
        "basic_blocks": basic_blocks,
        "instructions": instructions,
        "edges": edges,
        "truncated": {
            "ranges": len(ranges) >= MAX_CODE_RANGES,
            "instructions": len(instructions) >= MAX_INSTRUCTIONS,
            "functions": len(functions) >= MAX_FUNCTIONS,
            "basic_blocks": len(basic_blocks) >= MAX_BASIC_BLOCKS,
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


def write_blocks_csv(path: Path, payload: dict) -> Path:
    """Write basic block rows for spreadsheet review."""
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "range",
                "index",
                "address",
                "offset",
                "size",
                "instruction_count",
                "terminator",
                "outgoing",
            ]
        )
        for item in payload.get("basic_blocks", []):
            writer.writerow(
                [
                    item.get("range", ""),
                    item.get("index", ""),
                    _hex_or_empty(item.get("address")),
                    _hex_or_empty(item.get("offset")),
                    item.get("size", ""),
                    item.get("instruction_count", ""),
                    item.get("terminator", ""),
                    ";".join(_hex_or_empty(value) for value in item.get("outgoing", [])),
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
    data: bytes,
    ranges: list[dict],
    architecture: str,
    decoder: str,
) -> tuple[list[dict], list[dict], dict]:
    if decoder in {"auto", "capstone"}:
        capstone_result = decode_with_capstone(
            data, ranges, architecture, MAX_INSTRUCTIONS, MAX_INSTRUCTIONS_PER_RANGE
        )
        if capstone_result is not None:
            instructions, edges, decoder_info = capstone_result
            decoder_info["requested"] = decoder
            return instructions, edges, decoder_info

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
    decoder_info = {
        "engine": "builtin",
        "requested": decoder,
        "architecture": architecture,
    }
    if decoder == "capstone":
        decoder_info["fallback"] = "capstone unavailable or unsupported for this architecture"
    return instructions, edges, decoder_info


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


def _basic_blocks(
    ranges: list[dict],
    instructions: list[dict],
    edges: list[dict],
) -> list[dict]:
    blocks = []
    edges_by_source: dict[int, list[dict]] = {}
    for edge in edges:
        source = edge.get("source")
        if isinstance(source, int):
            edges_by_source.setdefault(source, []).append(edge)

    for code_range in ranges:
        range_name = code_range.get("name", "")
        rows = [item for item in instructions if item.get("range") == range_name]
        if not rows:
            continue
        range_start = code_range.get("virtual_address", 0)
        range_end = range_start + code_range.get("mapped_size", code_range.get("size", 0))
        addresses = {item.get("address") for item in rows if isinstance(item.get("address"), int)}
        starts = {rows[0]["address"]}
        for item in rows:
            address = item.get("address")
            size = item.get("size", 1)
            target = item.get("target")
            if isinstance(target, int) and range_start <= target < range_end:
                starts.add(target)
            if isinstance(address, int) and _ends_block(item.get("mnemonic", "")):
                next_address = address + max(size, 1)
                if next_address in addresses:
                    starts.add(next_address)

        ordered_starts = sorted(starts)
        for index, start in enumerate(ordered_starts):
            if len(blocks) >= MAX_BASIC_BLOCKS:
                return blocks
            stop = ordered_starts[index + 1] if index + 1 < len(ordered_starts) else range_end
            block_rows = [
                item
                for item in rows
                if isinstance(item.get("address"), int) and start <= item["address"] < stop
            ]
            if not block_rows:
                continue
            first = block_rows[0]
            last = block_rows[-1]
            end_address = last["address"] + max(last.get("size", 1), 1)
            outgoing = _block_outgoing(block_rows, edges_by_source, addresses)
            fallthrough = _fallthrough(last, addresses)
            if fallthrough is not None and fallthrough not in outgoing:
                outgoing.append(fallthrough)
            blocks.append(
                {
                    "range": range_name,
                    "index": index,
                    "address": start,
                    "offset": first.get("offset"),
                    "size": max(end_address - start, 0),
                    "instruction_count": len(block_rows),
                    "terminator": last.get("mnemonic", ""),
                    "outgoing": outgoing[:8],
                }
            )
    return blocks


def _block_outgoing(
    instructions: list[dict],
    edges_by_source: dict[int, list[dict]],
    addresses: set[object],
) -> list[int]:
    outgoing = []
    for item in instructions:
        address = item.get("address")
        if not isinstance(address, int):
            continue
        for edge in edges_by_source.get(address, []):
            target = edge.get("target")
            if isinstance(target, int) and target in addresses and target not in outgoing:
                outgoing.append(target)
    return outgoing


def _fallthrough(item: dict, addresses: set[object]) -> int | None:
    mnemonic = item.get("mnemonic", "")
    if mnemonic in RETURN_MNEMONICS or mnemonic in UNCONDITIONAL_BRANCHES:
        return None
    if mnemonic == "ret" or mnemonic.startswith("ret"):
        return None
    address = item.get("address")
    size = item.get("size", 1)
    if not isinstance(address, int):
        return None
    next_address = address + max(size, 1)
    return next_address if next_address in addresses else None


def _ends_block(mnemonic: str) -> bool:
    return (
        mnemonic in RETURN_MNEMONICS
        or mnemonic in UNCONDITIONAL_BRANCHES
        or mnemonic in CONDITIONAL_BRANCHES
        or mnemonic.startswith("j")
        or mnemonic.startswith("b.")
        or mnemonic.startswith("cb")
        or mnemonic.startswith("tb")
    )


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
