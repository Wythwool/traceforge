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
