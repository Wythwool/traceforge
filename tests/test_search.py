"""Tests for byte and string search helpers."""

import pytest

from traceforge.search import parse_hex_pattern, search_bytes, section_for_offset


def test_parse_hex_pattern_accepts_wildcards():
    assert parse_hex_pattern("4d 5a ?? 90") == (0x4D, 0x5A, None, 0x90)
    assert parse_hex_pattern("4d5a??90") == (0x4D, 0x5A, None, 0x90)


def test_parse_hex_pattern_rejects_bad_tokens():
    with pytest.raises(ValueError):
        parse_hex_pattern("4d ?f 90")


def test_search_bytes_finds_text_hex_regex_and_utf16le():
    wide = "WideMarker".encode("utf-16-le")
    data = b"\x00alpha marker beta\x00" + wide

    result = search_bytes(
        data,
        text="marker",
        hex_pattern="6d 61 ?? 6b 65 72",
        regex=r"alpha\s+marker",
        ignore_case=True,
        context=4,
    )

    found_types = {match["type"] for match in result["matches"]}
    assert {"text", "text_utf16le", "hex", "regex_ascii"} <= found_types
    assert any(match["offset_hex"] == "0x7" for match in result["matches"])
    assert all("context_ascii" in match for match in result["matches"])


def test_search_bytes_requires_a_query():
    with pytest.raises(ValueError):
        search_bytes(b"sample")


def test_section_for_offset_uses_file_ranges():
    format_info = {
        "details": {
            "sections": [
                {"name": ".text", "raw_offset": 0x200, "raw_size": 0x40},
                {"name": ".data", "raw_offset": 0x300, "raw_size": 0x20},
            ]
        }
    }

    assert section_for_offset(format_info, 0x210) == ".text"
    assert section_for_offset(format_info, 0x310) == ".data"
    assert section_for_offset(format_info, 0x100) is None
