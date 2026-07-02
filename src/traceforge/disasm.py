"""Optional Capstone-backed instruction decoding."""

from __future__ import annotations

import re
from typing import Any

_DIRECT_TARGET_RE = re.compile(r"-?(?:0x[0-9a-fA-F]+|\d+)")


def decode_with_capstone(
    data: bytes,
    ranges: list[dict],
    architecture: str,
    max_instructions: int,
    max_per_range: int,
) -> tuple[list[dict], list[dict], dict] | None:
    """Decode executable ranges with Capstone when the package is available."""
    capstone = _load_capstone()
    if capstone is None:
        return None
    config = _capstone_config(capstone, architecture)
    if config is None:
        return None

    arch, mode = config
    decoder = capstone.Cs(arch, mode)
    decoder.detail = False
    if hasattr(decoder, "skipdata"):
        decoder.skipdata = True

    instructions: list[dict] = []
    edges: list[dict] = []
    for code_range in ranges:
        if len(instructions) >= max_instructions:
            break
        start = int(code_range.get("offset", 0))
        size = min(
            int(code_range.get("mapped_size", code_range.get("size", 0))),
            max(len(data) - start, 0),
        )
        if start < 0 or size <= 0:
            continue
        base_address = int(code_range.get("virtual_address", start))
        raw = data[start : start + size]
        range_count = 0
        for insn in decoder.disasm(raw, base_address):
            if len(instructions) >= max_instructions or range_count >= max_per_range:
                break
            offset = start + (insn.address - base_address)
            mnemonic = str(insn.mnemonic).lower()
            operands = str(insn.op_str)
            item = {
                "range": code_range.get("name", ""),
                "offset": offset,
                "address": insn.address,
                "size": insn.size,
                "mnemonic": mnemonic,
                "operands": operands,
                "bytes": bytes(insn.bytes).hex(),
                "decoder": "capstone",
            }
            target = _direct_target(mnemonic, operands)
            if target is not None:
                item["target"] = target
                edges.append(
                    {
                        "source": insn.address,
                        "target": target,
                        "kind": _edge_kind(mnemonic),
                        "source_offset": offset,
                        "range": code_range.get("name", ""),
                    }
                )
            instructions.append(item)
            range_count += 1

    return (
        instructions,
        edges,
        {
            "engine": "capstone",
            "version": _capstone_version(capstone),
            "architecture": architecture,
        },
    )


def _load_capstone() -> Any | None:
    try:
        import capstone  # type: ignore[import-not-found]
    except ImportError:
        return None
    return capstone


def _capstone_config(capstone: Any, architecture: str) -> tuple[int, int] | None:
    if architecture == "x86":
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32
    if architecture == "x86_64":
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64
    if architecture == "arm":
        return capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN
    if architecture == "arm64":
        return capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
    return None


def _direct_target(mnemonic: str, operands: str) -> int | None:
    if not _is_control_transfer(mnemonic):
        return None
    first = operands.split(",", 1)[0].strip()
    if first.startswith("#"):
        first = first[1:].strip()
    if not _DIRECT_TARGET_RE.fullmatch(first):
        return None
    return int(first, 0)


def _is_control_transfer(mnemonic: str) -> bool:
    return (
        mnemonic in {"call", "jmp", "b", "bl", "br", "blr"}
        or mnemonic.startswith("j")
        or mnemonic.startswith("b.")
        or mnemonic.startswith("cb")
        or mnemonic.startswith("tb")
    )


def _edge_kind(mnemonic: str) -> str:
    if mnemonic in {"call", "bl", "blr"} or mnemonic.startswith("call"):
        return "call"
    return "branch"


def _capstone_version(capstone: Any) -> str:
    version = getattr(capstone, "cs_version", None)
    if callable(version):
        try:
            major, minor = version()
            return f"{major}.{minor}"
        except (TypeError, ValueError):
            pass
    return str(getattr(capstone, "__version__", ""))
