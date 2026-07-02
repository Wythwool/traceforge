"""Tests for local signature matching."""

import json

from traceforge import cli, core
from traceforge.signatures import match_signatures


def test_signature_matcher_supports_text_wide_hex_and_regex():
    data = (
        b"MZ\x90\x00"
        + b"Alpha VendorName marker\n"
        + "WideMarker".encode("utf-16-le")
        + b"\nhttps://sig.example.test/path\n"
    )
    signatures = [
        {
            "id": "custom.combo",
            "name": "Combo",
            "condition": "all",
            "patterns": [
                {"id": "mz", "hex": "4d 5a ?? 00", "offset": 0},
                {"id": "vendor", "text": "vendorname", "nocase": True},
                {"id": "wide", "text": "WideMarker", "wide": True, "ascii": False},
                {"id": "url", "regex": r"https://[a-z.]+/path"},
            ],
        }
    ]

    result = match_signatures(data, signatures, filename="sample.bin")

    assert result["match_count"] == 1
    match = result["matches"][0]
    assert match["id"] == "custom.combo"
    assert match["matched_pattern_count"] == 4
    assert {item["id"] for item in match["patterns"]} == {"mz", "vendor", "wide", "url"}


def test_signature_min_patterns(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"alpha beta gamma\n")
    signatures = tmp_path / "signatures.json"
    signatures.write_text(
        json.dumps(
            {
                "signatures": [
                    {
                        "id": "custom.two-of-three",
                        "min_patterns": 2,
                        "patterns": [
                            {"id": "alpha", "text": "alpha"},
                            {"id": "beta", "text": "beta"},
                            {"id": "missing", "text": "delta"},
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = core.evaluate_file_signatures(sample, signatures)

    assert result["match_count"] == 1
    assert result["matches"][0]["matched_pattern_count"] == 2


def test_scan_writes_builtin_signature_results(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 32)

    case_dir = core.scan_file(sample, cases_root=tmp_path / "cases")
    report = core.load_report(case_dir)

    assert report["extraction"]["signatures"]["match_count"] == 1
    assert report["extraction"]["signatures"]["matches"][0]["id"] == "format.pe.mz"
    assert (case_dir / "signature_matches.csv").is_file()
    assert "format.pe.mz" in (case_dir / "signature_matches.csv").read_text(
        encoding="utf-8"
    )


def test_signatures_cli_writes_json_and_csv(tmp_path, capsys):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"prefix MarkerOne suffix\n")
    signatures = tmp_path / "signatures.json"
    signatures.write_text(
        json.dumps(
            {
                "signatures": [
                    {
                        "id": "custom.marker",
                        "patterns": [{"id": "marker", "text": "MarkerOne"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    csv_path = tmp_path / "matches.csv"

    assert (
        cli.main(
            [
                "signatures",
                str(sample),
                "--signatures",
                str(signatures),
                "--csv",
                str(csv_path),
            ]
        )
        == 0
    )
    assert "custom.marker" in capsys.readouterr().out
    assert "custom.marker" in csv_path.read_text(encoding="utf-8")

    assert (
        cli.main(
            [
                "signatures",
                str(sample),
                "--signatures",
                str(signatures),
                "--json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["matches"][0]["id"] == "custom.marker"
