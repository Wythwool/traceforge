"""Tests for workbench artifact exports."""

import json

from traceforge.artifacts import render_hexdump, write_case_artifacts


def test_render_hexdump_formats_offsets_hex_and_ascii():
    assert render_hexdump(b"\x00ABC\xff", width=4) == (
        "00000000  00 41 42 43  |.ABC|\n"
        "00000004  ff           |.|\n"
    )


def test_write_case_artifacts_exports_workbench_files(tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"\x00ABC http://example.com\n")
    report = {
        "manifest": {
            "case_id": "sample-case",
            "file_name": "sample.bin",
            "source_path": str(source),
        },
        "extraction": {
            "strings": {
                "ascii": {"values": ["ABC http://example.com"]},
                "utf16le": {"values": ["wide string"]},
            },
            "chunks": {
                "records": [
                    {"index": 0, "offset": 0, "size": 24, "entropy": 3.5},
                ]
            },
            "format": {
                "details": {
                    "sections": [
                        {
                            "index": 0,
                            "name": ".text",
                            "raw_offset": 512,
                            "raw_size": 128,
                            "virtual_address": 4096,
                            "virtual_size": 128,
                            "characteristics": "0x60000020",
                            "readable": True,
                            "writable": False,
                            "executable": True,
                        }
                    ],
                    "resources": [
                        {
                            "type": "manifest",
                            "type_id": 24,
                            "name": "1",
                            "language": "1033",
                            "offset": 912,
                            "size": 32,
                            "sha256": "abc123",
                            "preview": "<assembly/>",
                        }
                    ],
                    "debug": [
                        {
                            "type": "codeview",
                            "offset": 1024,
                            "size": 48,
                            "codeview": {"pdb_path": "sample.pdb"},
                        }
                    ],
                    "tls": {"callbacks": [{"address": 4096, "rva": 4096}]},
                    "certificates": [
                        {
                            "type": "pkcs_signed_data",
                            "offset": 2048,
                            "size": 64,
                            "sha256": "def456",
                        }
                    ],
                    "imports": [
                        {
                            "library": "KERNEL32.dll",
                            "symbols": [{"name": "CreateFileW"}],
                        }
                    ],
                    "exports": [
                        {"module": "sample.dll", "name": "Run", "ordinal": 1},
                    ],
                    "observations": [
                        {
                            "id": "pe.entry",
                            "detail": "entry point maps to .text",
                            "evidence": ".text",
                        }
                    ],
                }
            },
            "symbols": {
                "imports": [{"name": "CreateFileW", "kind": "function"}],
                "exports": [{"name": "Run", "kind": "function"}],
                "symbols": [
                    {
                        "name": "Run",
                        "kind": "function",
                        "binding": "global",
                        "section_index": 1,
                        "value": 4096,
                        "size": 12,
                    }
                ],
                "relocations": [],
                "needed_libraries": [],
            },
            "code": {
                "ranges": [
                    {
                        "name": ".text",
                        "kind": "section",
                        "offset": 512,
                        "size": 128,
                        "virtual_address": 4096,
                        "permissions": "r-x",
                    }
                ],
                "functions": [{"name": "entry", "address": 4096, "offset": 512}],
                "instructions": [
                    {
                        "range": ".text",
                        "offset": 512,
                        "address": 4096,
                        "size": 1,
                        "mnemonic": "ret",
                        "operands": "",
                        "bytes": "c3",
                    }
                ],
                "edges": [],
            },
            "rules": {
                "matches": [
                    {
                        "id": "rule.network",
                        "level": "info",
                        "name": "Network",
                        "description": "network value",
                        "evidence": ["http://example.com"],
                    }
                ]
            },
        },
        "score": {
            "reasons": [
                {
                    "signal": "urls",
                    "detail": "URL found",
                    "evidence": ["http://example.com"],
                }
            ]
        },
    }

    paths = write_case_artifacts(tmp_path / "case", report)
    names = {path.name for path in paths}

    assert {
        "artifacts.json",
        "strings.csv",
        "chunks.csv",
        "sections.csv",
        "resources.csv",
        "debug.csv",
        "imports.csv",
        "exports.csv",
        "symbols.csv",
        "code.csv",
        "findings.csv",
        "hexdump.txt",
    } <= names
    assert "CreateFileW" in (tmp_path / "case" / "imports.csv").read_text()
    assert "sample.dll" in (tmp_path / "case" / "exports.csv").read_text()
    assert "Run" in (tmp_path / "case" / "symbols.csv").read_text()
    assert "manifest" in (tmp_path / "case" / "resources.csv").read_text()
    assert "sample.pdb" in (tmp_path / "case" / "debug.csv").read_text()
    assert "pkcs_signed_data" in (tmp_path / "case" / "debug.csv").read_text()
    assert "ret" in (tmp_path / "case" / "code.csv").read_text()
    assert ".text" in (tmp_path / "case" / "sections.csv").read_text()
    assert "rule.network" in (tmp_path / "case" / "findings.csv").read_text()
    assert "00000000" in (tmp_path / "case" / "hexdump.txt").read_text()

    manifest = json.loads((tmp_path / "case" / "artifacts.json").read_text())
    assert manifest["case_id"] == "sample-case"
    assert manifest["hexdump"]["written"] is True
