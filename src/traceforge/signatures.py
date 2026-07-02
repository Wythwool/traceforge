"""Local signature matching for static file inspection."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

from traceforge.formats import analyze_format
from traceforge.search import parse_hex_pattern, section_for_offset

DEFAULT_SIGNATURES: list[dict[str, Any]] = [
    {
        "id": "format.pe.mz",
        "name": "PE MZ header",
        "level": "info",
        "description": "File starts with an MZ executable header.",
        "condition": "all",
        "patterns": [{"id": "mz", "hex": "4d 5a", "offset": 0}],
    },
    {
        "id": "format.elf.magic",
        "name": "ELF header",
        "level": "info",
        "description": "File starts with an ELF header.",
        "condition": "all",
        "patterns": [{"id": "elf", "hex": "7f 45 4c 46", "offset": 0}],
    },
    {
        "id": "format.zip.local_header",
        "name": "ZIP local header",
        "level": "info",
        "description": "File starts with a ZIP local file header.",
        "condition": "all",
        "patterns": [{"id": "zip", "hex": "50 4b 03 04", "offset": 0}],
    },
    {
        "id": "format.wasm.magic",
        "name": "WASM header",
        "level": "info",
        "description": "File starts with a WebAssembly module header.",
        "condition": "all",
        "patterns": [{"id": "wasm", "hex": "00 61 73 6d", "offset": 0}],
    },
]

ASCII_RUN_RE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{4,}")
UTF16LE_RUN_RE = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){4,}")

DEFAULT_PATTERN_LIMIT = 20
DEFAULT_TOTAL_LIMIT = 500


def load_signatures(path: Path | None = None) -> list[dict[str, Any]]:
    """Load external signatures, or return the built-in signature set."""
    if path is None:
        return DEFAULT_SIGNATURES
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    signatures = payload.get("signatures", []) if isinstance(payload, dict) else payload
    if not isinstance(signatures, list):
        raise ValueError("signature file must contain a JSON list or {'signatures': [...]}")
    return signatures


def match_file_signatures(
    path: Path,
    signatures_path: Path | None = None,
    *,
    limit: int = DEFAULT_TOTAL_LIMIT,
) -> dict[str, Any]:
    """Match built-in or external signatures against one file."""
    source = Path(path)
    data = source.read_bytes()
    format_info = analyze_format(data, source.name)
    return match_signatures(
        data,
        load_signatures(signatures_path),
        filename=source.name,
        format_info=format_info,
        limit=limit,
    )


def match_signatures(
    data: bytes,
    signatures: list[dict[str, Any]] | None = None,
    *,
    filename: str = "",
    format_info: dict | None = None,
    limit: int = DEFAULT_TOTAL_LIMIT,
) -> dict[str, Any]:
    """Match signatures against a byte string."""
    if limit < 1:
        raise ValueError("limit must be at least one")
    active = DEFAULT_SIGNATURES if signatures is None else signatures
    fmt = format_info if format_info is not None else analyze_format(data, filename)
    state = {"remaining": limit, "truncated": False}
    matches = []
    for index, signature in enumerate(active):
        match = _match_signature(signature, index, data, fmt, state)
        if match is not None:
            matches.append(match)
        if state["remaining"] <= 0:
            state["truncated"] = True
            break
    return {
        "engine": "traceforge-signatures",
        "file_name": filename,
        "size": len(data),
        "format": fmt.get("kind", "raw"),
        "signature_count": len(active),
        "match_count": len(matches),
        "truncated": bool(state["truncated"]),
        "matches": matches,
    }


def write_signature_csv(path: Path, payload: dict[str, Any]) -> Path:
    """Write flat signature match rows to CSV."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as handle:
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
        for signature in payload.get("matches", []):
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
    return destination


def dumps(payload: dict[str, Any]) -> str:
    """Return signature results as formatted JSON."""
    return json.dumps(payload, indent=2) + "\n"


def _match_signature(
    signature: dict[str, Any],
    index: int,
    data: bytes,
    format_info: dict,
    state: dict[str, Any],
) -> dict[str, Any] | None:
    if not isinstance(signature, dict):
        raise ValueError(f"signature {index} must be an object")
    patterns = signature.get("patterns", [])
    if not isinstance(patterns, list) or not patterns:
        raise ValueError(f"signature {signature.get('id', index)!r} must define patterns")

    pattern_results = []
    for pattern_index, pattern in enumerate(patterns):
        if state["remaining"] <= 0:
            state["truncated"] = True
            break
        result = _match_pattern(pattern, pattern_index, data, format_info, state)
        if result["match_count"]:
            pattern_results.append(result)

    if not _condition_met(signature, len(patterns), len(pattern_results)):
        return None

    evidence = []
    for pattern in pattern_results:
        for match in pattern["matches"][:3]:
            evidence.append(
                f"{pattern['id']}@{match['offset_hex']} "
                f"{match['type']} {str(match['value'])[:80]}"
            )
    return {
        "id": signature.get("id", f"signature.{index}"),
        "name": signature.get("name", signature.get("id", f"signature.{index}")),
        "level": signature.get("level", "info"),
        "description": signature.get("description", ""),
        "condition": signature.get("condition", "any"),
        "pattern_count": len(patterns),
        "matched_pattern_count": len(pattern_results),
        "evidence": evidence[:10],
        "patterns": pattern_results,
    }


def _match_pattern(
    pattern: dict[str, Any],
    index: int,
    data: bytes,
    format_info: dict,
    state: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(pattern, dict):
        raise ValueError(f"pattern {index} must be an object")
    pattern_id = str(pattern.get("id") or f"p{index}")
    pattern_limit = _pattern_limit(pattern, state["remaining"])
    matches = _raw_pattern_matches(pattern, data, format_info, pattern_limit)
    if len(matches) >= pattern_limit:
        state["truncated"] = True
    state["remaining"] -= len(matches)
    return {
        "id": pattern_id,
        "type": _pattern_type(pattern),
        "match_count": len(matches),
        "matches": matches,
    }


def _raw_pattern_matches(
    pattern: dict[str, Any],
    data: bytes,
    format_info: dict,
    limit: int,
) -> list[dict[str, Any]]:
    if "text" in pattern:
        return _text_matches(pattern, data, format_info, limit)
    if "hex" in pattern:
        return _hex_matches(pattern, data, format_info, limit)
    if "regex" in pattern:
        return _regex_matches(pattern, data, format_info, limit)
    raise ValueError("pattern must define one of: text, hex, regex")


def _text_matches(
    pattern: dict[str, Any],
    data: bytes,
    format_info: dict,
    limit: int,
) -> list[dict[str, Any]]:
    value = str(pattern["text"])
    matches: list[dict[str, Any]] = []
    encodings = []
    if pattern.get("ascii", True):
        encodings.append(("text", value.encode("utf-8")))
    if pattern.get("wide", False):
        encodings.append(("text_utf16le", value.encode("utf-16-le")))
    for kind, needle in encodings:
        matches.extend(
            _literal_matches(
                data,
                needle,
                kind,
                value,
                bool(pattern.get("nocase", False)),
                pattern,
                format_info,
                limit - len(matches),
            )
        )
        if len(matches) >= limit:
            break
    return matches


def _literal_matches(
    data: bytes,
    needle: bytes,
    kind: str,
    value: str,
    nocase: bool,
    pattern: dict[str, Any],
    format_info: dict,
    limit: int,
) -> list[dict[str, Any]]:
    if not needle or limit <= 0:
        return []
    haystack = data.lower() if nocase else data
    target = needle.lower() if nocase else needle
    matches = []
    offset = haystack.find(target)
    while offset >= 0 and len(matches) < limit:
        if _offset_allowed(pattern, offset):
            matches.append(_match_record(data, offset, len(needle), kind, value, format_info))
        offset = haystack.find(target, offset + 1)
    return matches


def _hex_matches(
    pattern: dict[str, Any],
    data: bytes,
    format_info: dict,
    limit: int,
) -> list[dict[str, Any]]:
    parsed = parse_hex_pattern(str(pattern["hex"]))
    size = len(parsed)
    matches = []
    for offset in range(0, len(data) - size + 1):
        if not _offset_allowed(pattern, offset):
            continue
        for index, expected in enumerate(parsed):
            if expected is not None and data[offset + index] != expected:
                break
        else:
            matches.append(
                _match_record(data, offset, size, "hex", str(pattern["hex"]), format_info)
            )
            if len(matches) >= limit:
                break
    return matches


def _regex_matches(
    pattern: dict[str, Any],
    data: bytes,
    format_info: dict,
    limit: int,
) -> list[dict[str, Any]]:
    flags = re.IGNORECASE if pattern.get("nocase") else 0
    compiled = re.compile(str(pattern["regex"]), flags)
    encodings = ["ascii", "utf-16-le"] if pattern.get("wide", True) else ["ascii"]
    matches = []
    for encoding in encodings:
        kind = "regex_utf16le" if encoding == "utf-16-le" else "regex_ascii"
        width = 2 if encoding == "utf-16-le" else 1
        for start, text in _string_spans(data, encoding):
            for match in compiled.finditer(text):
                offset = start + match.start() * width
                if not _offset_allowed(pattern, offset):
                    continue
                size = max(1, len(match.group(0)) * width)
                matches.append(
                    _match_record(data, offset, size, kind, match.group(0), format_info)
                )
                if len(matches) >= limit:
                    return matches
    return matches


def _string_spans(data: bytes, encoding: str) -> list[tuple[int, str]]:
    regex = UTF16LE_RUN_RE if encoding == "utf-16-le" else ASCII_RUN_RE
    spans = []
    for match in regex.finditer(data):
        text = match.group().decode(encoding, errors="ignore")
        if len(text) >= 4:
            spans.append((match.start(), text.rstrip("\x00")))
    return spans


def _match_record(
    data: bytes,
    offset: int,
    size: int,
    kind: str,
    value: str,
    format_info: dict,
) -> dict[str, Any]:
    return {
        "type": kind,
        "value": value,
        "offset": offset,
        "offset_hex": f"0x{offset:x}",
        "size": size,
        "section": section_for_offset(format_info, offset) or "",
        "matched_hex": data[offset : offset + size].hex(" "),
    }


def _condition_met(signature: dict[str, Any], pattern_count: int, matched_count: int) -> bool:
    minimum = signature.get("min_patterns")
    if minimum is not None:
        if not isinstance(minimum, int) or minimum < 1:
            raise ValueError("min_patterns must be an integer greater than zero")
        return matched_count >= minimum
    condition = str(signature.get("condition", "any")).lower()
    if condition == "all":
        return matched_count == pattern_count
    if condition == "any":
        return matched_count > 0
    raise ValueError("signature condition must be any or all")


def _pattern_limit(pattern: dict[str, Any], remaining: int) -> int:
    configured = pattern.get("max_matches", DEFAULT_PATTERN_LIMIT)
    if not isinstance(configured, int) or configured < 1:
        raise ValueError("max_matches must be an integer greater than zero")
    return max(0, min(configured, remaining))


def _offset_allowed(pattern: dict[str, Any], offset: int) -> bool:
    if "offset" in pattern:
        return offset == _integer(pattern["offset"], "offset")
    if "offsets" in pattern:
        offsets = pattern["offsets"]
        if not isinstance(offsets, list):
            raise ValueError("offsets must be a list of integers")
        return offset in {_integer(value, "offsets") for value in offsets}
    return True


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _pattern_type(pattern: dict[str, Any]) -> str:
    if "text" in pattern:
        return "text"
    if "hex" in pattern:
        return "hex"
    if "regex" in pattern:
        return "regex"
    return "unknown"
