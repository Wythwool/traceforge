"""Tests for the traceforge command-line interface."""

from pathlib import Path

from traceforge import cli

CASE_FILES = {
    "manifest.json",
    "report.json",
    "report.html",
    "summary.md",
    "indicators.csv",
    "indicators.json",
    "graph.json",
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
}


def write_sample(path: Path) -> None:
    path.write_bytes(b"cli marker string\nhttp://cli.example.com/a\n")


def case_dirs(root: Path) -> list[Path]:
    cases = root / ".traceforge" / "cases"
    if not cases.is_dir():
        return []
    return sorted(entry for entry in cases.iterdir() if entry.is_dir())


def test_scan_creates_case(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    sample = tmp_path / "sample.bin"
    write_sample(sample)
    assert cli.main(["scan", str(sample)]) == 0
    cases = case_dirs(tmp_path)
    assert len(cases) == 1
    assert CASE_FILES <= {entry.name for entry in cases[0].iterdir()}
    assert cases[0].name in capsys.readouterr().out


def test_scan_dir_scans_each_regular_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "input"
    target.mkdir()
    write_sample(target / "one.bin")
    (target / "two.bin").write_bytes(b"second marker text 10.9.8.7\n")
    (target / "nested").mkdir()
    assert cli.main(["scan-dir", str(target)]) == 0
    assert len(case_dirs(tmp_path)) == 2


def test_scan_dir_recursive_scans_nested_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "input"
    nested = target / "nested" / "deeper"
    nested.mkdir(parents=True)
    write_sample(target / "one.bin")
    (nested / "two.bin").write_bytes(b"recursive marker http://nested.example.com\n")

    assert cli.main(["scan-dir", str(target), "--recursive"]) == 0
    assert len(case_dirs(tmp_path)) == 2


def test_scan_dir_with_no_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "empty"
    target.mkdir()
    assert cli.main(["scan-dir", str(target)]) == 0
    assert "no regular files" in capsys.readouterr().out


def test_report_and_export_regenerate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample = tmp_path / "sample.bin"
    write_sample(sample)
    assert cli.main(["scan", str(sample)]) == 0
    case_dir = case_dirs(tmp_path)[0]

    for name in ("report.html", "summary.md", "graph.json"):
        (case_dir / name).unlink()
    assert cli.main(["report", str(case_dir)]) == 0
    for name in ("report.html", "summary.md", "graph.json"):
        assert (case_dir / name).is_file()

    for name in ("indicators.csv", "indicators.json"):
        (case_dir / name).unlink()
    assert cli.main(["export", str(case_dir)]) == 0
    for name in ("indicators.csv", "indicators.json"):
        assert (case_dir / name).is_file()


def test_artifacts_regenerate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample = tmp_path / "sample.bin"
    write_sample(sample)
    assert cli.main(["scan", str(sample)]) == 0
    case_dir = case_dirs(tmp_path)[0]

    for name in (
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
    ):
        (case_dir / name).unlink()
    assert cli.main(["artifacts", str(case_dir), "--source", str(sample)]) == 0
    for name in (
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
    ):
        assert (case_dir / name).is_file()


def test_index_and_diff_commands(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    left = tmp_path / "left.bin"
    right = tmp_path / "right.bin"
    left.write_bytes(b"left marker http://left.example.com\n")
    right.write_bytes(b"right marker http://right.example.com\n")

    assert cli.main(["scan", str(left)]) == 0
    assert cli.main(["scan", str(right)]) == 0
    cases_root = tmp_path / ".traceforge" / "cases"

    assert cli.main(["index", str(cases_root)]) == 0
    assert (cases_root / "case_index.json").is_file()

    cases = case_dirs(tmp_path)
    output = tmp_path / "comparison"
    assert cli.main(["diff", str(cases[0]), str(cases[1]), "-o", str(output)]) == 0
    assert (output / "diff.json").is_file()
    assert (output / "diff.md").is_file()


def test_search_command_prints_matches(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"alpha marker beta\n")

    assert cli.main(["search", str(sample), "--text", "marker", "--hex", "6d 61 ?? 6b"]) == 0
    out = capsys.readouterr().out
    assert "0x6" in out
    assert "text" in out
    assert "hex" in out


def test_scan_missing_file_fails(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["scan", str(tmp_path / "missing.bin")]) == 2
    assert "not a regular file" in capsys.readouterr().err


def test_report_requires_existing_case(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    empty = tmp_path / "empty-case"
    empty.mkdir()
    assert cli.main(["report", str(empty)]) == 2
    assert cli.main(["export", str(empty)]) == 2
    assert "report.json" in capsys.readouterr().err
