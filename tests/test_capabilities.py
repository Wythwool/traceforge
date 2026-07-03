"""Tests for static capability grouping."""

import json

from traceforge import cli, core
from traceforge.capabilities import analyze_capabilities


def test_capability_analysis_groups_common_static_evidence():
    extraction = core.extract(
        (
            b"InternetOpenA CryptEncrypt CreateProcessA RegOpenKeyA "
            b"VirtualAlloc GetComputerNameA C:\\Temp\\demo.txt "
            b"HKEY_CURRENT_USER\\Software\\Demo http://cap.example.test\n"
        ),
        "sample.bin",
    )
    payload = analyze_capabilities(extraction)
    ids = {item["id"] for item in payload["categories"]}

    assert {"network", "crypto", "process", "registry", "filesystem"} <= ids
    assert "memory-code" in ids
    assert "system-info" in ids


def test_capabilities_cli_writes_json_and_csv(tmp_path, capsys):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"socket connect AES CreateFileA http://cli.example.test\n")
    csv_path = tmp_path / "capabilities.csv"

    assert cli.main(["capabilities", str(sample), "--csv", str(csv_path)]) == 0
    out = capsys.readouterr().out

    assert "network" in out
    assert "crypto" in out
    assert "network" in csv_path.read_text(encoding="utf-8")

    assert cli.main(["capabilities", str(sample), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["engine"] == "traceforge-capabilities"
    assert "network" in payload["summary"]


def test_scan_writes_capability_outputs(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"WinHttpOpen CreateFileA SHA256 http://scan.example.test\n")

    case_dir = core.scan_file(sample, cases_root=tmp_path / "cases")
    report = core.load_report(case_dir)

    assert "capabilities" in report["extraction"]
    assert "network" in report["extraction"]["capabilities"]["summary"]
    assert (case_dir / "capabilities.csv").is_file()
    assert "## Capabilities" in (case_dir / "summary.md").read_text(encoding="utf-8")
    assert "Capabilities" in (case_dir / "report.html").read_text(encoding="utf-8")
