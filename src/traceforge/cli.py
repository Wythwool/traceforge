"""Command-line interface for TraceForge."""

import argparse
import json
import re
import sys
from pathlib import Path

from traceforge import __version__, core
from traceforge.carve import carve_file
from traceforge.code_map import dumps as dump_code
from traceforge.code_map import inspect_code_file, write_code_csv
from traceforge.search import search_file
from traceforge.symbols import dumps as dump_symbols
from traceforge.symbols import inspect_symbols_file, write_symbols_csv


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
    scan.add_argument(
        "--cases-root",
        type=Path,
        help="case storage root; defaults to .traceforge/cases",
    )

    scan_dir = sub.add_parser(
        "scan-dir", help="scan regular files inside a directory"
    )
    scan_dir.add_argument("directory", type=Path, help="path to a directory")
    scan_dir.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="scan nested directories and skip .traceforge case output",
    )
    scan_dir.add_argument(
        "--cases-root",
        type=Path,
        help="case storage root; defaults to .traceforge/cases",
    )

    report = sub.add_parser(
        "report", help="regenerate report.html, summary.md and graph.json for a case"
    )
    report.add_argument("case_dir", type=Path, help="path to an existing case folder")

    export = sub.add_parser(
        "export", help="regenerate indicators.csv and indicators.json for a case"
    )
    export.add_argument("case_dir", type=Path, help="path to an existing case folder")

    artifacts = sub.add_parser(
        "artifacts", help="regenerate CSV and hexdump workbench files for a case"
    )
    artifacts.add_argument("case_dir", type=Path, help="path to an existing case folder")
    artifacts.add_argument(
        "--source",
        type=Path,
        help="optional source file path for hexdump regeneration",
    )
    artifacts.add_argument(
        "--hexdump-limit",
        type=int,
        default=8192,
        help="maximum source bytes to render into hexdump.txt",
    )

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

    search_cmd = sub.add_parser("search", help="search bytes, strings, and regex in one file")
    search_cmd.add_argument("file", type=Path, help="path to a regular file")
    search_cmd.add_argument("--text", help="literal text to search as UTF-8 and UTF-16LE")
    search_cmd.add_argument("--hex", dest="hex_pattern", help="hex bytes, with ?? wildcards")
    search_cmd.add_argument("--regex", help="regular expression over extracted string runs")
    search_cmd.add_argument(
        "-i",
        "--ignore-case",
        action="store_true",
        help="case-insensitive text and regex search",
    )
    search_cmd.add_argument(
        "--context",
        type=int,
        default=16,
        help="bytes of context before and after each match",
    )
    search_cmd.add_argument(
        "--limit",
        type=int,
        default=200,
        help="maximum matches to return",
    )
    search_cmd.add_argument("--json", action="store_true", help="print full JSON output")

    symbols = sub.add_parser("symbols", help="inspect visible symbols and relocations")
    symbols.add_argument("file", type=Path, help="path to a regular file")
    symbols.add_argument("--json", action="store_true", help="print full JSON output")
    symbols.add_argument("--csv", type=Path, help="write a flat symbol CSV")

    code = sub.add_parser("code", help="map executable ranges and instruction previews")
    code.add_argument("file", type=Path, help="path to a regular file")
    code.add_argument("--json", action="store_true", help="print full JSON output")
    code.add_argument("--csv", type=Path, help="write instruction preview CSV")

    index = sub.add_parser("index", help="write case_index.json for a cases root")
    index.add_argument(
        "cases_root",
        nargs="?",
        type=Path,
        default=core.default_cases_root(),
        help="case storage root; defaults to .traceforge/cases",
    )

    diff = sub.add_parser("diff", help="compare two case folders")
    diff.add_argument("left_case_dir", type=Path, help="first case folder")
    diff.add_argument("right_case_dir", type=Path, help="second case folder")
    diff.add_argument(
        "-o",
        "--output",
        type=Path,
        help="output directory for diff.json and diff.md",
    )
    return parser


def _fail(message: str) -> int:
    print(f"traceforge: {message}", file=sys.stderr)
    return 2


def _cmd_scan(path: Path, cases_root: Path | None) -> int:
    if not path.is_file():
        return _fail(f"not a regular file: {path}")
    try:
        case_dir = core.scan_file(path, cases_root=cases_root)
    except OSError as exc:
        return _fail(f"could not scan {path}: {exc}")
    print(f"case created: {case_dir}")
    return 0


def _cmd_scan_dir(
    directory: Path, recursive: bool = False, cases_root: Path | None = None
) -> int:
    if not directory.is_dir():
        return _fail(f"not a directory: {directory}")
    files = core.iter_regular_files(directory, recursive=recursive)
    if not files:
        print(f"no regular files found in {directory}")
        return 0
    failures = 0
    for path in files:
        try:
            case_dir = core.scan_file(path, cases_root=cases_root)
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


def _cmd_artifacts(
    case_dir: Path,
    source: Path | None,
    hexdump_limit: int,
) -> int:
    if not (case_dir / "report.json").is_file():
        return _fail(f"no report.json in {case_dir}; run 'traceforge scan' first")
    if source is not None and not source.is_file():
        return _fail(f"source file not found: {source}")
    if hexdump_limit < 0:
        return _fail("--hexdump-limit must be zero or greater")
    try:
        paths = core.regenerate_artifacts(case_dir, source, hexdump_limit)
    except OSError as exc:
        return _fail(f"could not write artifacts for {case_dir}: {exc}")
    for path in paths:
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


def _cmd_search(args: argparse.Namespace) -> int:
    if not args.file.is_file():
        return _fail(f"not a regular file: {args.file}")
    try:
        payload = search_file(
            args.file,
            text=args.text,
            hex_pattern=args.hex_pattern,
            regex=args.regex,
            ignore_case=args.ignore_case,
            context=args.context,
            limit=args.limit,
        )
    except (OSError, ValueError, re.error) as exc:
        return _fail(f"could not search {args.file}: {exc}")
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    if not payload["matches"]:
        print("no matches")
        return 0
    for match in payload["matches"]:
        section = f" section={match['section']}" if match["section"] else ""
        print(
            f"{match['offset_hex']} {match['type']}{section} "
            f"size={match['size']} {match['context_ascii']}"
        )
    if payload["truncated"]:
        print(f"matches truncated at {payload['match_count']}")
    return 0


def _cmd_symbols(args: argparse.Namespace) -> int:
    if not args.file.is_file():
        return _fail(f"not a regular file: {args.file}")
    try:
        payload = inspect_symbols_file(args.file)
        if args.csv is not None:
            write_symbols_csv(args.csv, payload)
            print(f"wrote {args.csv}")
    except OSError as exc:
        return _fail(f"could not inspect symbols for {args.file}: {exc}")
    if args.json:
        print(dump_symbols(payload), end="")
        return 0
    for name, rows in (
        ("import", payload.get("imports", [])),
        ("export", payload.get("exports", [])),
        ("symbol", payload.get("symbols", [])),
    ):
        for row in rows:
            if row.get("name"):
                print(f"{name} {row['name']} {row.get('kind', '')}".rstrip())
    for block in payload.get("relocations", []):
        count = len(block.get("entries", []))
        print(f"relocations page=0x{block.get('page_rva', 0):x} count={count}")
    if not any(payload.get(key) for key in ("imports", "exports", "symbols", "relocations")):
        print("no visible symbols or relocations")
    return 0


def _cmd_code(args: argparse.Namespace) -> int:
    if not args.file.is_file():
        return _fail(f"not a regular file: {args.file}")
    try:
        payload = inspect_code_file(args.file)
        if args.csv is not None:
            write_code_csv(args.csv, payload)
            print(f"wrote {args.csv}")
    except OSError as exc:
        return _fail(f"could not inspect code for {args.file}: {exc}")
    if args.json:
        print(dump_code(payload), end="")
        return 0
    print(
        f"architecture {payload.get('architecture', 'unknown')} "
        f"ranges={len(payload.get('ranges', []))} "
        f"functions={len(payload.get('functions', []))} "
        f"instructions={len(payload.get('instructions', []))}"
    )
    for item in payload.get("functions", [])[:32]:
        offset = item.get("offset")
        offset_text = "" if offset is None else f" offset=0x{offset:x}"
        print(f"function 0x{item['address']:x} {item['name']}{offset_text}")
    for item in payload.get("instructions", [])[:64]:
        operands = f" {item['operands']}" if item.get("operands") else ""
        print(f"0x{item['address']:x} {item['mnemonic']}{operands}".rstrip())
    return 0


def _cmd_index(cases_root: Path) -> int:
    if not cases_root.exists():
        return _fail(f"cases root does not exist: {cases_root}")
    if not cases_root.is_dir():
        return _fail(f"not a directory: {cases_root}")
    try:
        path = core.write_case_index(cases_root)
    except OSError as exc:
        return _fail(f"could not write case index: {exc}")
    print(f"wrote {path}")
    return 0


def _cmd_diff(
    left_case_dir: Path, right_case_dir: Path, output: Path | None = None
) -> int:
    for case_dir in (left_case_dir, right_case_dir):
        if not (case_dir / "report.json").is_file():
            return _fail(f"no report.json in {case_dir}; run 'traceforge scan' first")
    try:
        paths = core.write_case_comparison(left_case_dir, right_case_dir, output)
    except OSError as exc:
        return _fail(f"could not write case diff: {exc}")
    for path in paths:
        print(f"wrote {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args.file, args.cases_root)
    if args.command == "scan-dir":
        return _cmd_scan_dir(args.directory, args.recursive, args.cases_root)
    if args.command == "report":
        return _cmd_report(args.case_dir)
    if args.command == "export":
        return _cmd_export(args.case_dir)
    if args.command == "artifacts":
        return _cmd_artifacts(args.case_dir, args.source, args.hexdump_limit)
    if args.command == "identify":
        return _cmd_identify(args.file)
    if args.command == "rules":
        return _cmd_rules(args.file, args.rules_path)
    if args.command == "carve":
        return _cmd_carve(args.file, args.output)
    if args.command == "search":
        return _cmd_search(args)
    if args.command == "symbols":
        return _cmd_symbols(args)
    if args.command == "code":
        return _cmd_code(args)
    if args.command == "index":
        return _cmd_index(args.cases_root)
    return _cmd_diff(args.left_case_dir, args.right_case_dir, args.output)
