"""Command-line interface for TraceForge."""

import argparse
import json
import sys
from pathlib import Path

from traceforge import __version__, core
from traceforge.carve import carve_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="traceforge",
        description="Read local files as bytes, extract facts, and write case reports.",
    )
    parser.add_argument(
        "--version", action="version", version=f"traceforge {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan one file and create a case folder")
    scan.add_argument("file", type=Path, help="path to a regular file")

    scan_dir = sub.add_parser(
        "scan-dir", help="scan every regular file directly inside a directory"
    )
    scan_dir.add_argument("directory", type=Path, help="path to a directory")

    report = sub.add_parser(
        "report", help="regenerate report.html, summary.md and graph.json for a case"
    )
    report.add_argument("case_dir", type=Path, help="path to an existing case folder")

    export = sub.add_parser(
        "export", help="regenerate indicators.csv and indicators.json for a case"
    )
    export.add_argument("case_dir", type=Path, help="path to an existing case folder")

    identify = sub.add_parser("identify", help="print format metadata for one file")
    identify.add_argument("file", type=Path, help="path to a regular file")

    rules = sub.add_parser("rules", help="evaluate local rules for one file")
    rules.add_argument("file", type=Path, help="path to a regular file")
    rules.add_argument(
        "--rules",
        dest="rules_path",
        type=Path,
        help="optional JSON rule file; built-in rules are used when omitted",
    )

    carve = sub.add_parser("carve", help="carve embedded artifacts from one file")
    carve.add_argument("file", type=Path, help="path to a regular file")
    carve.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("carved"),
        help="output directory for carved files",
    )
    return parser


def _fail(message: str) -> int:
    print(f"traceforge: {message}", file=sys.stderr)
    return 2


def _cmd_scan(path: Path) -> int:
    if not path.is_file():
        return _fail(f"not a regular file: {path}")
    try:
        case_dir = core.scan_file(path)
    except OSError as exc:
        return _fail(f"could not scan {path}: {exc}")
    print(f"case created: {case_dir}")
    return 0


def _cmd_scan_dir(directory: Path) -> int:
    if not directory.is_dir():
        return _fail(f"not a directory: {directory}")
    files = core.iter_regular_files(directory)
    if not files:
        print(f"no regular files found in {directory}")
        return 0
    failures = 0
    for path in files:
        try:
            case_dir = core.scan_file(path)
        except OSError as exc:
            failures += 1
            print(f"traceforge: could not scan {path}: {exc}", file=sys.stderr)
            continue
        print(f"case created: {case_dir}")
    print(f"scanned {len(files) - failures} of {len(files)} file(s)")
    return 1 if failures else 0


def _cmd_report(case_dir: Path) -> int:
    if not (case_dir / "report.json").is_file():
        return _fail(f"no report.json in {case_dir}; run 'traceforge scan' first")
    for path in core.regenerate_reports(case_dir):
        print(f"wrote {path}")
    return 0


def _cmd_export(case_dir: Path) -> int:
    if not (case_dir / "report.json").is_file():
        return _fail(f"no report.json in {case_dir}; run 'traceforge scan' first")
    for path in core.regenerate_exports(case_dir):
        print(f"wrote {path}")
    return 0


def _cmd_identify(path: Path) -> int:
    if not path.is_file():
        return _fail(f"not a regular file: {path}")
    try:
        payload = core.identify_file(path)
    except OSError as exc:
        return _fail(f"could not identify {path}: {exc}")
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_rules(path: Path, rules_path: Path | None) -> int:
    if not path.is_file():
        return _fail(f"not a regular file: {path}")
    if rules_path is not None and not rules_path.is_file():
        return _fail(f"rule file not found: {rules_path}")
    try:
        payload = core.evaluate_file_rules(path, rules_path)
    except (OSError, ValueError) as exc:
        return _fail(f"could not evaluate rules for {path}: {exc}")
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_carve(path: Path, output: Path) -> int:
    if not path.is_file():
        return _fail(f"not a regular file: {path}")
    try:
        payload = carve_file(path, output)
    except OSError as exc:
        return _fail(f"could not carve {path}: {exc}")
    print(json.dumps(payload, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args.file)
    if args.command == "scan-dir":
        return _cmd_scan_dir(args.directory)
    if args.command == "report":
        return _cmd_report(args.case_dir)
    if args.command == "export":
        return _cmd_export(args.case_dir)
    if args.command == "identify":
        return _cmd_identify(args.file)
    if args.command == "rules":
        return _cmd_rules(args.file, args.rules_path)
    return _cmd_carve(args.file, args.output)
