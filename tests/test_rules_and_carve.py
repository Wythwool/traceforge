"""Tests for local rules, carving, and added CLI commands."""

import json

from traceforge import cli, core
from traceforge.carve import carve_embedded


def test_custom_rule_file(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"alpha VendorName version v1.2\n")
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom.vendor",
                        "name": "Vendor",
                        "level": "info",
                        "any": [{"contains": "VendorName"}, {"regex": "v[0-9]+\\.[0-9]+"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = core.evaluate_file_rules(sample, rules)
    assert result["match_count"] == 1
    assert result["matches"][0]["id"] == "custom.vendor"
    assert result["matches"][0]["evidence"]


def test_carve_embedded_artifact(tmp_path):
    data = b"prefix" + b"MZ" + b"\x00" * 20 + b"tail"
    output = tmp_path / "carved"
    manifest = carve_embedded(data, output)
    assert manifest["count"] == 1
    carved_path = output / "artifact_000_pe_00000006.pe.bin"
    assert carved_path.is_file()
    assert carved_path.read_bytes().startswith(b"MZ")
    assert (output / "carve_manifest.json").is_file()


def test_identify_rules_and_carve_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"prefix http://cli.example.com\n" + b"MZ" + b"\x00" * 4)

    assert cli.main(["identify", str(sample)]) == 0
    identify_payload = json.loads(capsys.readouterr().out)
    assert identify_payload["kind"] == "raw"
    assert identify_payload["embedded"][0]["kind"] == "pe"

    assert cli.main(["rules", str(sample)]) == 0
    rules_payload = json.loads(capsys.readouterr().out)
    assert rules_payload["match_count"] >= 1

    assert cli.main(["carve", str(sample), "-o", "out"]) == 0
    carve_payload = json.loads(capsys.readouterr().out)
    assert carve_payload["count"] == 1
    assert (tmp_path / "out" / "carve_manifest.json").is_file()
