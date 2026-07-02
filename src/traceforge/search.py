"""Byte and string search helpers for local analysis work."""

from __future__ import annotations

import re
from pathlib import Path

from traceforge.formats import analyze_format

ASCII_RUN_RE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{4,}")
UTF16LE_RUN_RE = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){4,}")


def search_file(
    path: Path,
    *,
    text: str | None = None,
    hex_pattern: str | None = None,
    regex: str | None = None,
    ignore_case: bool = False,
    context: int = 16,
    limit: int = 200,
) -> dict:
    """Search one file and return bounded, structured matches."""
    path = Path(path)
    return search_bytes(
        path.read_bytes(),
        filename=path.name,
        text=text,
        hex_pattern=hex_pattern,
        regex=regex,
        ignore_case=ignore_case,
        context=context,
        limit=limit,
    )


def search_bytes(
    data: bytes,
    *,
    filename: str = "",
    text: str | None = None,
    hex_pattern: str | None = None,
    regex: str | None = None,
    ignore_case: bool = False,
    context: int = 16,
    limit: int = 200,
) -> dict:
    """Search bytes using literal text, hex patterns, and regex over strings."""
    if context < 0:
        raise ValueError("context must be zero or greater")
    if limit < 1:
        raise ValueError("limit must be at least one")
    if text is None and hex_pattern is None and regex is None:
        raise ValueError("provide --text, --hex, or --regex")

    format_info = analyze_format(data, filename)
    matches: list[dict] = []
    if text is not None:
        matches.extend(
            _literal_matches(
                data,
                text.encode("utf-8"),
                "text",
                text,
                ignore_case,
                context,
                limit - len(matches),
                format_info,
            )
        )
        if len(matches) < limit:
            matches.extend(
                _literal_matches(
                    data,
                    text.encode("utf-16-le"),
                    "text_utf16le",
                    text,
                    ignore_case,
                    context,
                    limit - len(matches),
                    format_info,
                )
            )
    if hex_pattern is not None and len(matches) < limit:
        pattern = parse_hex_pattern(hex_pattern)
        matches.extend(
            _hex_matches(
                data,
                pattern,
                "hex",
                hex_pattern,
                context,
                limit - len(matches),
                format_info,
            )
        )
    if regex is not None and len(matches) < limit:
        matches.extend(
            _regex_matches(
                data,
                regex,
                ignore_case,
                context,
                limit - len(matches),
                format_info,
            )
        )

    matches.sort(key=lambda item: (item["offset"], item["type"]))
    truncated = len(matches) >= limit
    return {
        "file_name": filename,
        "size": len(data),
        "format": format_info["kind"],
        "match_count": len(matches),
        "truncated": truncated,
        "matches": matches[:limit],
    }


def parse_hex_pattern(value: str) -> tuple[int | None, ...]:
    """Parse a byte pattern such as '4d 5a ?? 90'."""
    raw = value.strip().replace("_", " ")
    if not raw:
        raise ValueError("hex pattern is empty")
    if any(char.isspace() for char in raw):
        tokens = raw.split()
    else:
        compact = raw.replace("-", "")
        if len(compact) % 2:
            raise ValueError("compact hex pattern must have an even length")
        tokens = [compact[index : index + 2] for index in range(0, len(compact), 2)]

    parsed: list[int | None] = []
    for token in tokens:
        if token in {"?", "??"}:
            parsed.append(None)
            continue
        if len(token) != 2 or "?" in token:
            raise ValueError(f"unsupported hex token: {token}")
        try:
            parsed.append(int(token, 16))
        except ValueError as exc:
            raise ValueError(f"invalid hex token: {token}") from exc
    return tuple(parsed)


def _literal_matches(
    data: bytes,
    needle: bytes,
    kind: str,
    value: str,
    ignore_case: bool,
    context: int,
    limit: int,
    format_info: dict,
) -> list[dict]:
    if not needle or limit <= 0:
        return []
    haystack = data.lower() if ignore_case else data
    target = needle.lower() if ignore_case else needle
    matches = []
    offset = haystack.find(target)
    while offset >= 0 and len(matches) < limit:
        matches.append(
            _match_record(data, offset, len(needle), kind, value, context, format_info)
        )
        offset = haystack.find(target, offset + 1)
    return matches


def _hex_matches(
    data: bytes,
    pattern: tuple[int | None, ...],
    kind: str,
    value: str,
    context: int,
    limit: int,
    format_info: dict,
) -> list[dict]:
    if not pattern or limit <= 0:
        return []
    size = len(pattern)
    matches = []
    for offset in range(0, len(data) - size + 1):
        for index, expected in enumerate(pattern):
            if expected is not None and data[offset + index] != expected:
                break
        else:
            matches.append(_match_record(data, offset, size, kind, value, context, format_info))
            if len(matches) >= limit:
                break
    return matches


def _regex_matches(
    data: bytes,
    pattern: str,
    ignore_case: bool,
    context: int,
    limit: int,
    format_info: dict,
) -> list[dict]:
    flags = re.IGNORECASE if ignore_case else 0
    compiled = re.compile(pattern, flags)
    matches = []
    for encoding, spans in (
        ("regex_ascii", _string_spans(data, "ascii")),
        ("regex_utf16le", _string_spans(data, "utf-16-le")),
    ):
        for start, text in spans:
            for match in compiled.finditer(text):
                offset = start + match.start() * (2 if encoding.endswith("utf16le") else 1)
                size = max(1, len(match.group(0)) * (2 if encoding.endswith("utf16le") else 1))
                matches.append(
                    _match_record(
                        data,
                        offset,
                        size,
                        encoding,
                        match.group(0),
                        context,
                        format_info,
                    )
                )
                if len(matches) >= limit:
                    return matches
    return matches


def _string_spans(data: bytes, encoding: str) -> list[tuple[int, str]]:
    regex = UTF16LE_RUN_RE if encoding == "utf-16-le" else ASCII_RUN_RE
    spans = []
    for match in regex.finditer(data):
        raw = match.group()
        text = raw.decode(encoding, errors="ignore")
        if len(text) >= 4:
            spans.append((match.start(), text.rstrip("\x00")))
    return spans


def _match_record(
    data: bytes,
    offset: int,
    size: int,
    kind: str,
    value: str,
    context: int,
    format_info: dict,
) -> dict:
    start = max(0, offset - context)
    end = min(len(data), offset + size + context)
    preview = data[start:end]
    return {
        "type": kind,
        "value": value,
        "offset": offset,
        "offset_hex": f"0x{offset:x}",
        "size": size,
        "section": section_for_offset(format_info, offset) or "",
        "context_start": start,
        "context_hex": preview.hex(" "),
        "context_ascii": _printable_preview(preview),
        "matched_hex": data[offset : offset + size].hex(" "),
    }


def section_for_offset(format_info: dict, offset: int) -> str | None:
    """Return the section or segment name that owns a file offset when known."""
    details = format_info.get("details", {})
    for section in details.get("sections", []):
        start = _first_int(section, "raw_offset", "offset", "fileoff")
        size = _first_int(section, "raw_size", "size", "filesize")
        if start is not None and size is not None and start <= offset < start + size:
            return section.get("name") or section.get("segment") or section.get("label")
    for segment in details.get("segments", []):
        start = _first_int(segment, "fileoff", "offset")
        size = _first_int(segment, "filesize", "size")
        if start is not None and size is not None and start <= offset < start + size:
            return segment.get("name")
    return None


def _first_int(values: dict, *keys: str) -> int | None:
    for key in keys:
        value = values.get(key)
        if isinstance(value, int):
            return value
    return None


def _printable_preview(data: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data)
