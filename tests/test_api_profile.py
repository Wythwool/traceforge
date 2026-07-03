"""Tests for import and API-family profiles."""

import json
import struct

from traceforge import cli, core
from traceforge.api_profile import analyze_api_profile


def build_pe_with_imports() -> bytes:
    data = bytearray(2048)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<II", data, opt + 56, 0x3000, 0x400)
    struct.pack_into("<HH", data, opt + 68, 3, 0x8140)
    directories = opt + 112

    section = opt + 0xF0
    data[section : section + 8] = b".text\x00\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        data,
        section + 8,
        0x800,
        0x1000,
        0x600,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )

    def rva(offset: int) -> int:
        return 0x1000 + offset - 0x200

    import_dir = 0x300
    struct.pack_into("<II", data, directories + 8, rva(import_dir), 0x80)
    struct.pack_into("<IIIII", data, import_dir, rva(0x3C0), 0, 0, rva(0x340), rva(0x3E0))
    struct.pack_into(
        "<IIIII",
        data,
        import_dir + 20,
        rva(0x3D0),
        0,
        0,
        rva(0x350),
        rva(0x3F0),
    )

    data[0x340 : 0x340 + len(b"KERNEL32.dll\x00")] = b"KERNEL32.dll\x00"
    data[0x350 : 0x350 + len(b"WS2_32.dll\x00")] = b"WS2_32.dll\x00"
    struct.pack_into("<H", data, 0x380, 0)
    data[0x382 : 0x382 + len(b"CreateFileW\x00")] = b"CreateFileW\x00"
    struct.pack_into("<H", data, 0x3A0, 0)
    data[0x3A2 : 0x3A2 + len(b"connect\x00")] = b"connect\x00"
    struct.pack_into("<QQ", data, 0x3C0, rva(0x380), 0)
    struct.pack_into("<QQ", data, 0x3D0, rva(0x3A0), 0)
    data[0x200:0x204] = b"\x90\xc3\x00\x00"
    return bytes(data)


def test_api_profile_groups_import_families():
    extraction = core.extract(build_pe_with_imports(), "imports.exe")
    payload = analyze_api_profile(extraction, "imports.exe")
    families = {item["id"] for item in payload["families"]}
    libraries = {item["normalized"] for item in payload["libraries"]}

    assert payload["engine"] == "traceforge-api-profile"
    assert payload["import_count"] == 2
    assert {"filesystem", "network"} <= families
    assert {"kernel32", "ws2_32"} <= libraries
    assert extraction["apis"]["family_count"] == 2


def test_apis_cli_writes_json_and_csv(tmp_path, capsys):
    sample = tmp_path / "imports.exe"
    sample.write_bytes(build_pe_with_imports())
    csv_path = tmp_path / "apis.csv"

    assert cli.main(["apis", str(sample), "--csv", str(csv_path)]) == 0
    out = capsys.readouterr().out

    assert "families=2" in out
    assert "filesystem" in out
    assert "network" in csv_path.read_text(encoding="utf-8")

    assert cli.main(["apis", str(sample), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["engine"] == "traceforge-api-profile"
    assert payload["import_count"] == 2


def test_scan_writes_api_profile_outputs(tmp_path):
    sample = tmp_path / "imports.exe"
    sample.write_bytes(build_pe_with_imports())

    case_dir = core.scan_file(sample, cases_root=tmp_path / "cases")
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))

    assert report["extraction"]["apis"]["family_count"] == 2
    assert (case_dir / "api_profile.csv").is_file()
    assert "filesystem" in (case_dir / "findings.csv").read_text(encoding="utf-8")
