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
                    "fingerprints": {
                        "imphash": "a" * 32,
                        "delay_imphash": "b" * 32,
                        "rich_hash": "c" * 32,
                        "version_info_hash": "d" * 32,
                    },
                    "rich_header": {
                        "xor_key": "0xa5a5a5a5",
                        "entry_count": 1,
                        "entries": [
                            {
                                "index": 0,
                                "product_id": 258,
                                "build_id": 4660,
                                "count": 5,
                            }
                        ],
                    },
                    "version_info": [
                        {
                            "fixed_file_info": {
                                "file_version": "1.2.3.4",
                                "product_version": "5.6.7.8",
                                "file_type": "0x00000001",
                                "file_os": "0x00040004",
                            },
                            "strings": {
                                "FileDescription": "TraceForge sample",
                                "ProductName": "TraceForge Test",
                            },
                            "translations": [
                                {"language": "0x0409", "codepage": "0x04b0"}
                            ],
                        }
                    ],
                    "exceptions": {
                        "count": 1,
                        "entries": [
                            {
                                "index": 0,
                                "begin_rva": 4096,
                                "end_rva": 4112,
                                "unwind_info_rva": 5120,
                                "begin_section": ".text",
                            }
                        ],
                    },
                    "load_config": {
                        "size": 160,
                        "guard_flags": "0x500",
                        "guard_flag_names": [
                            "cf_instrumented",
                            "cf_function_table_present",
                        ],
                        "security_cookie": {
                            "address": 5368713232,
                            "rva": 4112,
                            "offset": 528,
                            "section": ".text",
                        },
                        "guard_cf_function_table": {
                            "address": 5368715264,
                            "rva": 6144,
                            "offset": 2560,
                            "section": ".text",
                        },
                        "guard_cf_function_count": 2,
                    },
                    "delay_imports": [
                        {
                            "library": "USER32.dll",
                            "iat_rva": 5296,
                            "name_table_rva": 5280,
                            "symbols": [
                                {
                                    "name": "MessageBoxW",
                                    "iat_rva": 5296,
                                    "iat_address": 5368714416,
                                    "thunk_rva": 5280,
                                }
                            ],
                        }
                    ],
                    "clr": {
                        "runtime_version": "2.5",
                        "flags": "0x9",
                        "flag_names": ["ilonly", "strong_name_signed"],
                        "entry_point_token": "0x6000001",
                        "metadata": {
                            "metadata_version": "1.1",
                            "version": "v4.0.30319",
                            "stream_count": 2,
                            "streams": [
                                {"name": "#~", "offset": 64, "size": 32},
                                {"name": "#Strings", "offset": 96, "size": 24},
                            ],
                        },
                    },
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
                "basic_blocks": [
                    {
                        "range": ".text",
                        "index": 0,
                        "address": 4096,
                        "offset": 512,
                        "size": 1,
                        "instruction_count": 1,
                        "terminator": "ret",
                        "outgoing": [],
                    }
                ],
                "xrefs": [
                    {
                        "kind": "call",
                        "source": 4096,
                        "source_offset": 512,
                        "source_function": "entry",
                        "mnemonic": "call",
                        "target": 4100,
                        "target_kind": "function",
                        "target_name": "sub_1004",
                        "target_range": ".text",
                        "target_offset": 516,
                    }
                ],
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
            "callgraph": {
                "engine": "traceforge-callgraph",
                "format": "pe",
                "architecture": "x86_64",
                "node_count": 2,
                "edge_count": 1,
                "function_count": 2,
                "import_count": 0,
                "external_count": 0,
                "internal_call_count": 1,
                "import_call_count": 0,
                "branch_count": 0,
                "functions": [
                    {
                        "id": "function:1000",
                        "kind": "function",
                        "name": "entry",
                        "address": 4096,
                    },
                    {
                        "id": "function:1004",
                        "kind": "function",
                        "name": "sub_1004",
                        "address": 4100,
                    },
                ],
                "imports": [],
                "externals": [],
                "edges": [
                    {
                        "source": "function:1000",
                        "source_kind": "function",
                        "source_name": "entry",
                        "source_address": 4096,
                        "target": "function:1004",
                        "target_kind": "function",
                        "target_name": "sub_1004",
                        "target_address": 4100,
                        "kind": "call",
                        "indirect": False,
                        "count": 1,
                        "sites": [{"address": 4096}],
                    }
                ],
            },
            "profile": {
                "observations": [
                    {
                        "id": "pe.tls-callbacks",
                        "level": "medium",
                        "title": "TLS callbacks",
                        "detail": "TLS callback table is present",
                        "evidence": "1",
                    }
                ]
            },
            "apis": {
                "families": [
                    {
                        "id": "filesystem",
                        "confidence": "low",
                        "name": "Filesystem",
                        "description": "File and directory access APIs.",
                        "evidence": [
                            {
                                "library": "KERNEL32.dll",
                                "name": "CreateFileW",
                            }
                        ],
                    }
                ],
                "libraries": [
                    {
                        "name": "KERNEL32.dll",
                        "category": "native-runtime",
                        "import_count": 1,
                    }
                ],
                "imports": [
                    {
                        "library": "KERNEL32.dll",
                        "name": "CreateFileW",
                        "families": ["filesystem"],
                    }
                ],
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
        "pe_metadata.csv",
        "imports.csv",
        "exports.csv",
        "symbols.csv",
        "relocations.csv",
        "code.csv",
        "blocks.csv",
        "xrefs.csv",
        "callgraph.csv",
        "callgraph.dot",
        "format_profile.csv",
        "api_profile.csv",
        "findings.csv",
        "hexdump.txt",
    } <= names
    assert "CreateFileW" in (tmp_path / "case" / "imports.csv").read_text()
    assert "sample.dll" in (tmp_path / "case" / "exports.csv").read_text()
    assert "Run" in (tmp_path / "case" / "symbols.csv").read_text()
    assert "block" in (tmp_path / "case" / "relocations.csv").read_text()
    assert "manifest" in (tmp_path / "case" / "resources.csv").read_text()
    assert "sample.pdb" in (tmp_path / "case" / "debug.csv").read_text()
    assert "pkcs_signed_data" in (tmp_path / "case" / "debug.csv").read_text()
    assert "cf_instrumented" in (tmp_path / "case" / "pe_metadata.csv").read_text()
    assert "MessageBoxW" in (tmp_path / "case" / "pe_metadata.csv").read_text()
    assert "TraceForge sample" in (tmp_path / "case" / "pe_metadata.csv").read_text()
    assert "rich_header.entry" in (tmp_path / "case" / "pe_metadata.csv").read_text()
    assert "MessageBoxW" in (tmp_path / "case" / "imports.csv").read_text()
    assert "ret" in (tmp_path / "case" / "code.csv").read_text()
    assert "0x1000" in (tmp_path / "case" / "blocks.csv").read_text()
    assert "sub_1004" in (tmp_path / "case" / "xrefs.csv").read_text()
    assert "sub_1004" in (tmp_path / "case" / "callgraph.csv").read_text()
    assert "digraph traceforge_callgraph" in (
        tmp_path / "case" / "callgraph.dot"
    ).read_text()
    assert "pe.tls-callbacks" in (tmp_path / "case" / "format_profile.csv").read_text()
    assert "CreateFileW" in (tmp_path / "case" / "api_profile.csv").read_text()
    assert ".text" in (tmp_path / "case" / "sections.csv").read_text()
    assert "rule.network" in (tmp_path / "case" / "findings.csv").read_text()
    assert "00000000" in (tmp_path / "case" / "hexdump.txt").read_text()

    manifest = json.loads((tmp_path / "case" / "artifacts.json").read_text())
    assert manifest["case_id"] == "sample-case"
    assert manifest["hexdump"]["written"] is True
