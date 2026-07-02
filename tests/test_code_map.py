"""Tests for static executable code mapping."""

import json
import struct

from traceforge import cli, core
from traceforge.code_map import inspect_code, write_blocks_csv, write_code_csv, write_xrefs_csv


def build_pe_with_call() -> bytes:
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
    data[0x200:0x209] = b"\xe8\x03\x00\x00\x00\x90\x90\x90\xc3"
    return bytes(data)


def test_inspect_code_maps_pe_entry_and_call_target():
    result = inspect_code(build_pe_with_call(), "sample.exe")

    assert result["architecture"] == "x86_64"
    assert result["decoder"]["engine"] in {"builtin", "capstone"}
    assert result["ranges"][0]["name"] == ".text"
    assert result["entry_point"]["address"] == 0x140001000
    assert result["entry_point"]["offset"] == 0x200
    assert result["instructions"][0]["mnemonic"] == "call"
    assert result["instructions"][0]["target"] == 0x140001008
    assert {item["address"] for item in result["functions"]} >= {0x140001000, 0x140001008}
    assert {item["address"] for item in result["basic_blocks"]} >= {0x140001000, 0x140001008}
    assert result["edges"][0]["kind"] == "call"
    assert result["xrefs"][0]["source_function"] == "entry"
    assert result["xrefs"][0]["target_kind"] == "function"
    assert result["xrefs"][0]["target_name"] == "sub_140001008"
    assert result["edges"][0]["target_name"] == "sub_140001008"


def test_write_code_csv(tmp_path):
    result = inspect_code(build_pe_with_call(), "sample.exe")
    output = tmp_path / "code.csv"

    write_code_csv(output, result)

    text = output.read_text(encoding="utf-8")
    assert "call" in text
    assert "0x140001000" in text


def test_write_blocks_csv(tmp_path):
    result = inspect_code(build_pe_with_call(), "sample.exe", decoder="builtin")
    output = tmp_path / "blocks.csv"

    write_blocks_csv(output, result)

    text = output.read_text(encoding="utf-8")
    assert "0x140001000" in text
    assert "ret" in text


def test_write_xrefs_csv(tmp_path):
    result = inspect_code(build_pe_with_call(), "sample.exe", decoder="builtin")
    output = tmp_path / "xrefs.csv"

    write_xrefs_csv(output, result)

    text = output.read_text(encoding="utf-8")
    assert "entry" in text
    assert "sub_140001008" in text


def test_code_command_json_and_csv(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe_with_call())
    csv_path = tmp_path / "code.csv"
    blocks_path = tmp_path / "blocks.csv"
    xrefs_path = tmp_path / "xrefs.csv"

    assert (
        cli.main(
            [
                "code",
                str(sample),
                "--decoder",
                "builtin",
                "--json",
                "--csv",
                str(csv_path),
                "--blocks-csv",
                str(blocks_path),
                "--xrefs-csv",
                str(xrefs_path),
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    payload = json.loads(out[out.index("{") :])
    assert payload["architecture"] == "x86_64"
    assert payload["decoder"]["engine"] == "builtin"
    assert payload["xrefs"][0]["target_name"] == "sub_140001008"
    assert csv_path.is_file()
    assert blocks_path.is_file()
    assert xrefs_path.is_file()


def test_scan_embeds_code_map_in_case_outputs(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe_with_call())

    case_dir = core.scan_file(sample, cases_root=tmp_path / "cases")
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    graph = json.loads((case_dir / "graph.json").read_text(encoding="utf-8"))
    html = (case_dir / "report.html").read_text(encoding="utf-8")

    assert report["extraction"]["code"]["architecture"] == "x86_64"
    assert "call" in (case_dir / "code.csv").read_text(encoding="utf-8")
    assert "0x140001000" in (case_dir / "blocks.csv").read_text(encoding="utf-8")
    assert "sub_140001008" in (case_dir / "xrefs.csv").read_text(encoding="utf-8")
    assert {"code_range", "function", "basic_block", "code_xref"} <= {
        node["type"] for node in graph["nodes"]
    }
    assert "Code Map" in html
    assert "Code xrefs" in html
