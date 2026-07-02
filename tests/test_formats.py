"""Tests for offline format parsers."""

import io
import json
import struct
import zipfile

from traceforge import core
from traceforge.formats import analyze_format


def build_minimal_pe() -> bytes:
    data = bytearray(1024)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0x12345678, 0, 0, 0xF0, 0x2022)
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<II", data, opt + 56, 0x2000, 0x400)
    struct.pack_into("<HH", data, opt + 68, 3, 0x8140)
    section = opt + 0xF0
    data[section : section + 8] = b".text\x00\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        data,
        section + 8,
        0x100,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    data[0x200:0x204] = b"\x90\x90\xc3\x00"
    return bytes(data)


def wasm_name(value: str) -> bytes:
    raw = value.encode("utf-8")
    return bytes([len(raw)]) + raw


def wasm_section(section_id: int, payload: bytes) -> bytes:
    assert len(payload) < 128
    return bytes([section_id, len(payload)]) + payload


def build_minimal_wasm() -> bytes:
    import_payload = b"\x01" + wasm_name("env") + wasm_name("clock") + b"\x00\x00"
    export_payload = b"\x01" + wasm_name("main") + b"\x00\x00"
    return (
        b"\x00asm"
        + (1).to_bytes(4, "little")
        + wasm_section(2, import_payload)
        + wasm_section(7, export_payload)
    )


def build_minimal_elf() -> bytes:
    data = bytearray(256)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        2,
        0x3E,
        1,
        0x400000,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        1,
        5,
        0,
        0x400000,
        0x400000,
        len(data),
        len(data),
        0x1000,
    )
    return bytes(data)


def build_minimal_macho() -> bytes:
    library = b"/usr/lib/libSystem.B.dylib\x00"
    command_size = 24 + len(library)
    command_size += (8 - command_size % 8) % 8
    data = bytearray(32 + command_size)
    struct.pack_into("<I", data, 0, 0xFEEDFACF)
    struct.pack_into("<IIIIIII", data, 4, 0x01000007, 3, 2, 1, command_size, 0, 0)
    command = 32
    struct.pack_into("<IIIIII", data, command, 0xC, command_size, 24, 0, 0, 0)
    data[command + 24 : command + 24 + len(library)] = library
    return bytes(data)


def build_zip() -> bytes:
    body = io.BytesIO()
    with zipfile.ZipFile(body, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        archive.writestr("com/example/App.class", b"\xca\xfe\xba\xbe")
    return body.getvalue()


def test_pe_parser_extracts_sections_and_header():
    result = analyze_format(build_minimal_pe() + b"overlay", "sample.exe")
    assert result["kind"] == "pe"
    details = result["details"]
    assert details["format"] == "pe32+"
    assert details["machine"] == "amd64"
    assert details["entry_section"] == ".text"
    assert "executable_image" in details["characteristic_flags"]
    assert "dynamic_base" in details["dll_characteristic_flags"]
    assert details["sections"][0]["name"] == ".text"
    assert details["sections"][0]["executable"] is True
    assert details["sections"][0]["permissions"] == "r-x"
    assert len(details["sections"][0]["sha256"]) == 64
    assert details["overlay"]["present"] is True
    assert details["overlay"]["size"] == len(b"overlay")


def test_elf_parser_extracts_program_headers():
    result = analyze_format(build_minimal_elf(), "sample.elf")
    assert result["kind"] == "elf"
    details = result["details"]
    assert details["machine"] == "x86_64"
    assert details["program_headers"][0]["type_name"] == "load"
    assert details["program_headers"][0]["permissions"] == "r-x"


def test_macho_parser_extracts_load_commands_and_libraries():
    result = analyze_format(build_minimal_macho(), "sample")
    assert result["kind"] == "macho"
    details = result["details"]
    assert details["cpu"] == "x86_64"
    assert details["load_commands"][0]["name"] == "LC_LOAD_DYLIB"
    assert details["linked_libraries"] == ["/usr/lib/libSystem.B.dylib"]
    assert details["imports"][0]["library"] == "/usr/lib/libSystem.B.dylib"


def test_wasm_parser_extracts_imports_and_exports():
    result = analyze_format(build_minimal_wasm(), "mod.wasm")
    assert result["kind"] == "wasm"
    assert result["details"]["version"] == 1
    assert result["details"]["imports"] == [{"module": "env", "name": "clock", "kind": 0}]
    assert result["details"]["exports"] == [{"name": "main", "kind": 0, "index": 0}]


def test_zip_container_parser_detects_jar_entries():
    result = analyze_format(build_zip(), "sample.jar")
    assert result["kind"] == "jar"
    assert result["details"]["container_kind"] == "jar"
    assert result["details"]["jar"]["class_count"] == 1
    assert result["details"]["jar"]["manifest_present"] is True


def test_scan_report_contains_format_and_rules(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_minimal_pe())
    case_dir = core.scan_file(sample, cases_root=tmp_path / "cases")
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    assert report["extraction"]["format"]["kind"] == "pe"
    assert report["extraction"]["rules"]["match_count"] >= 1
