"""Tests for executable symbol inspection."""

import json
import struct

from traceforge import cli, core
from traceforge.symbols import inspect_symbols, write_symbols_csv


def build_elf_with_symbols() -> bytes:
    data = bytearray(1024)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    shoff = 0x200
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        3,
        0x3E,
        1,
        0,
        0,
        shoff,
        0,
        64,
        0,
        0,
        64,
        6,
        1,
    )
    shstr = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00.dynamic\x00.rela.plt\x00"
    dynstr = b"\x00puts\x00exported_func\x00libc.so.6\x00sample.so\x00$ORIGIN/lib\x00"
    data[0x100 : 0x100 + len(shstr)] = shstr
    data[0x140 : 0x140 + len(dynstr)] = dynstr
    dynsym = 0x180
    struct.pack_into("<IBBHQQ", data, dynsym + 24, dynstr.index(b"puts"), 0x12, 0, 0, 0, 0)
    struct.pack_into(
        "<IBBHQQ",
        data,
        dynsym + 48,
        dynstr.index(b"exported_func"),
        0x12,
        0,
        1,
        0x401000,
        16,
    )
    dynamic = 0x380
    struct.pack_into("<qQ", data, dynamic, 1, dynstr.index(b"libc.so.6"))
    struct.pack_into("<qQ", data, dynamic + 16, 14, dynstr.index(b"sample.so"))
    struct.pack_into("<qQ", data, dynamic + 32, 29, dynstr.index(b"$ORIGIN/lib"))
    struct.pack_into("<qQ", data, dynamic + 48, 0, 0)
    rela = 0x3C0
    struct.pack_into("<QQq", data, rela, 0x404000, (1 << 32) | 7, 0)

    def section(
        index: int,
        name: bytes,
        kind: int,
        offset: int,
        size: int,
        link: int,
        entsize: int,
    ):
        struct.pack_into(
            "<IIQQQQIIQQ",
            data,
            shoff + index * 64,
            shstr.index(name),
            kind,
            0,
            0,
            offset,
            size,
            link,
            0,
            8,
            entsize,
        )

    section(1, b".shstrtab", 3, 0x100, len(shstr), 0, 0)
    section(2, b".dynstr", 3, 0x140, len(dynstr), 0, 0)
    section(3, b".dynsym", 11, dynsym, 72, 2, 24)
    section(4, b".dynamic", 6, dynamic, 64, 2, 16)
    section(5, b".rela.plt", 4, rela, 24, 3, 24)
    return bytes(data)


def test_inspect_symbols_reads_elf_imports_exports_and_libraries():
    result = inspect_symbols(build_elf_with_symbols(), "sample.elf")

    assert result["format"] == "elf"
    assert result["needed_libraries"] == ["libc.so.6"]
    assert result["dynamic"]["soname"] == "sample.so"
    assert result["dynamic"]["runpath"] == "$ORIGIN/lib"
    assert [item["name"] for item in result["imports"]] == ["puts"]
    assert [item["name"] for item in result["exports"]] == ["exported_func"]
    assert result["relocations"][0]["section"] == ".rela.plt"
    assert result["relocations"][0]["entries"][0]["type"] == "jump_slot"
    assert result["relocations"][0]["entries"][0]["symbol_name"] == "puts"


def test_write_symbols_csv(tmp_path):
    result = inspect_symbols(build_elf_with_symbols(), "sample.elf")
    output = tmp_path / "symbols.csv"

    write_symbols_csv(output, result)

    text = output.read_text(encoding="utf-8")
    assert "puts" in text
    assert "exported_func" in text


def test_symbols_command_json_and_csv(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    sample = tmp_path / "sample.elf"
    sample.write_bytes(build_elf_with_symbols())
    csv_path = tmp_path / "out.csv"

    relocations_csv = tmp_path / "relocations.csv"
    assert (
        cli.main(
            [
                "symbols",
                str(sample),
                "--json",
                "--csv",
                str(csv_path),
                "--relocations-csv",
                str(relocations_csv),
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    payload = json.loads(out.split("\n", 2)[2])
    assert payload["needed_libraries"] == ["libc.so.6"]
    assert csv_path.is_file()
    assert "jump_slot" in relocations_csv.read_text(encoding="utf-8")


def test_scan_embeds_symbols_in_case_outputs(tmp_path):
    sample = tmp_path / "sample.elf"
    sample.write_bytes(build_elf_with_symbols())

    case_dir = core.scan_file(sample, cases_root=tmp_path / "cases")
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    graph = json.loads((case_dir / "graph.json").read_text(encoding="utf-8"))

    assert report["extraction"]["symbols"]["needed_libraries"] == ["libc.so.6"]
    assert report["extraction"]["format"]["details"]["dynamic"]["soname"] == "sample.so"
    assert report["extraction"]["symbols"]["dynamic"]["runpath"] == "$ORIGIN/lib"
    assert [item["name"] for item in report["extraction"]["symbols"]["imports"]] == ["puts"]
    assert "exported_func" in (case_dir / "symbols.csv").read_text(encoding="utf-8")
    assert "jump_slot" in (case_dir / "relocations.csv").read_text(encoding="utf-8")
    assert "symbol" in {node["type"] for node in graph["nodes"]}
