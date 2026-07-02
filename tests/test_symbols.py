"""Tests for executable symbol inspection."""

import json
import struct

from traceforge import cli
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
        5,
        1,
    )
    shstr = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00.dynamic\x00"
    dynstr = b"\x00puts\x00exported_func\x00libc.so.6\x00"
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
    dynamic = 0x1D0
    struct.pack_into("<qQ", data, dynamic, 1, dynstr.index(b"libc.so.6"))
    struct.pack_into("<qQ", data, dynamic + 16, 0, 0)

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
    section(4, b".dynamic", 6, dynamic, 32, 2, 16)
    return bytes(data)


def test_inspect_symbols_reads_elf_imports_exports_and_libraries():
    result = inspect_symbols(build_elf_with_symbols(), "sample.elf")

    assert result["format"] == "elf"
    assert result["needed_libraries"] == ["libc.so.6"]
    assert [item["name"] for item in result["imports"]] == ["puts"]
    assert [item["name"] for item in result["exports"]] == ["exported_func"]


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

    assert cli.main(["symbols", str(sample), "--json", "--csv", str(csv_path)]) == 0
    out = capsys.readouterr().out
    payload = json.loads(out.split("\n", 1)[1])
    assert payload["needed_libraries"] == ["libc.so.6"]
    assert csv_path.is_file()
