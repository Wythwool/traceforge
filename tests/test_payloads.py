"""Tests for payload extraction."""

import json
import struct

from traceforge import cli, core
from traceforge.payloads import extract_payloads


def build_pe_with_resource_and_overlay() -> bytes:
    data = bytearray(2048)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0x12345678, 0, 0, 0xF0, 0x2022)
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<II", data, opt + 56, 0x3000, 0x400)
    struct.pack_into("<HH", data, opt + 68, 3, 0x8140)
    directories = opt + 112
    struct.pack_into("<II", data, directories + 2 * 8, 0x1100, 0x100)

    section = opt + 0xF0
    data[section : section + 8] = b".rsrc\x00\x00\x00"
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
        0x40000040,
    )

    resource = 0x300
    struct.pack_into("<IIHHHH", data, resource, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, resource + 16, 24, 0x80000018)
    struct.pack_into("<IIHHHH", data, resource + 0x18, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, resource + 0x28, 1, 0x80000030)
    struct.pack_into("<IIHHHH", data, resource + 0x30, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, resource + 0x40, 1033, 0x48)
    manifest = b"<assembly><trustInfo/></assembly>"
    data[0x390 : 0x390 + len(manifest)] = manifest
    struct.pack_into("<IIII", data, resource + 0x48, 0x1190, len(manifest), 65001, 0)
    return bytes(data) + b"OVERLAY"


def test_extract_payloads_writes_sections_resources_and_overlay(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe_with_resource_and_overlay())

    manifest = extract_payloads(sample, tmp_path / "out")

    assert manifest["format"] == "pe"
    assert {item["kind"] for item in manifest["records"]} == {
        "section",
        "resource",
        "overlay",
    }
    by_kind = {item["kind"]: item for item in manifest["records"]}
    assert (tmp_path / "out" / by_kind["resource"]["path"]).read_bytes().startswith(
        b"<assembly>"
    )
    assert (tmp_path / "out" / by_kind["overlay"]["path"]).read_bytes() == b"OVERLAY"
    assert (tmp_path / "out" / "extract_manifest.json").is_file()
    assert (tmp_path / "out" / "extracted_payloads.csv").is_file()


def test_extract_payloads_can_limit_targets(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe_with_resource_and_overlay())

    manifest = core.extract_file_payloads_to_dir(
        sample,
        tmp_path / "resources",
        sections=False,
        resources=True,
        overlay=False,
    )

    assert [item["kind"] for item in manifest["records"]] == ["resource"]


def test_extract_cli_prints_json_manifest(tmp_path, capsys):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe_with_resource_and_overlay())
    output = tmp_path / "cli-out"

    assert (
        cli.main(
            [
                "extract",
                str(sample),
                "--resources",
                "--overlay",
                "-o",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)

    assert payload["count"] == 2
    assert {item["kind"] for item in payload["records"]} == {"resource", "overlay"}
    assert (output / "extract_manifest.json").is_file()
