"""Core extraction and case management for TraceForge.

Reads local files as bytes only. No network access, no execution of inputs.
"""

import hashlib
import json
import math
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from traceforge import __version__, bundles, case_db, schemas, workspace
from traceforge import ruleset as ruleset_tools
from traceforge.annotations import (
    ensure_annotations,
    update_annotations,
)
from traceforge.annotations import (
    load_annotations as load_case_annotations_file,
)
from traceforge.artifacts import write_case_artifacts
from traceforge.code_map import inspect_code
from traceforge.formats import analyze_format
from traceforge.graph import build_graph
from traceforge.hunt import write_hunt
from traceforge.payloads import extract_payloads as extract_file_payloads
from traceforge.reports import (
    write_all_reports,
    write_indicator_exports,
    write_report_html,
    write_summary_md,
)
from traceforge.rules import evaluate_rules, load_rules
from traceforge.score import score_extraction
from traceforge.signatures import match_file_signatures
from traceforge.signatures import match_signatures as match_signature_set
from traceforge.symbols import inspect_symbols
from traceforge.viewer import write_case_viewer
from traceforge.workspace_viewer import write_workspace_viewer

CHUNK_SIZE = 4096
WINDOW_SIZE = 256
MIN_STRING_LENGTH = 4
FIRST_BYTES_LENGTH = 16

# Storage caps keep report.json bounded for very large inputs; totals are recorded.
MAX_STORED_STRINGS = 5000
MAX_STORED_CHUNKS = 2048

ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LENGTH)
UTF16LE_STRING_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING_LENGTH)

_TLDS = (
    "com", "net", "org", "io", "co", "us", "uk", "de", "fr", "nl", "ru", "cn", "jp",
    "in", "au", "ca", "br", "es", "it", "ch", "se", "pl", "eu", "gov", "edu", "mil",
    "int", "info", "biz", "xyz", "top", "site", "online", "onion",
)

URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + "|".join(_TLDS) + r")\b",
    re.IGNORECASE,
)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)
WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|*?]+")
UNIX_PATH_RE = re.compile(
    r"(?<!\w)/(?:usr|etc|bin|sbin|home|var|opt|tmp|lib|dev|proc|sys|root|srv)/[^\s\"'<>]+"
)
REGISTRY_PATH_RE = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS"
    r"|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"'<>]+",
    re.IGNORECASE,
)

INDICATOR_PATTERNS = (
    ("url", URL_RE),
    ("domain", DOMAIN_RE),
    ("ipv4", IPV4_RE),
    ("path", WINDOWS_PATH_RE),
    ("path", UNIX_PATH_RE),
    ("registry_path", REGISTRY_PATH_RE),
)


def hash_digests(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def extract_ascii_strings(data: bytes) -> list[str]:
    return [match.group().decode("ascii") for match in ASCII_STRING_RE.finditer(data)]


def extract_utf16le_strings(data: bytes) -> list[str]:
    return [match.group().decode("utf-16-le") for match in UTF16LE_STRING_RE.finditer(data)]


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, rounded to 4 decimals."""
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def window_entropy_summary(data: bytes) -> dict:
    values = [
        shannon_entropy(data[offset : offset + WINDOW_SIZE])
        for offset in range(0, len(data), WINDOW_SIZE)
    ]
    if not values:
        return {"window_size": WINDOW_SIZE, "count": 0, "min": 0.0, "max": 0.0, "mean": 0.0}
    return {
        "window_size": WINDOW_SIZE,
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "mean": round(sum(values) / len(values), 4),
    }


def chunk_summary(data: bytes) -> dict:
    records = []
    for index, offset in enumerate(range(0, len(data), CHUNK_SIZE)):
        part = data[offset : offset + CHUNK_SIZE]
        records.append(
            {
                "index": index,
                "offset": offset,
                "size": len(part),
                "entropy": shannon_entropy(part),
            }
        )
    total = len(records)
    return {
        "chunk_size": CHUNK_SIZE,
        "total": total,
        "truncated": total > MAX_STORED_CHUNKS,
        "records": records[:MAX_STORED_CHUNKS],
    }


def extract_indicators(ascii_values: list[str], utf16_values: list[str]) -> list[dict]:
    found: set[tuple[str, str, str]] = set()
    for source, values in (("ascii", ascii_values), ("utf16le", utf16_values)):
        text = "\n".join(values)
        for kind, pattern in INDICATOR_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group()
                if kind == "domain":
                    value = value.lower()
                found.add((kind, value, source))
    return [
        {"type": kind, "value": value, "source": source}
        for kind, value, source in sorted(found)
    ]


def extract(data: bytes, filename: str = "") -> dict:
    """Extract all facts from a byte string."""
    ascii_values = extract_ascii_strings(data)
    utf16_values = extract_utf16le_strings(data)
    result = {
        "size": len(data),
        "hashes": hash_digests(data),
        "first_bytes_hex": data[:FIRST_BYTES_LENGTH].hex(),
        "strings": {
            "min_length": MIN_STRING_LENGTH,
            "ascii": {
                "total": len(ascii_values),
                "values": ascii_values[:MAX_STORED_STRINGS],
            },
            "utf16le": {
                "total": len(utf16_values),
                "values": utf16_values[:MAX_STORED_STRINGS],
            },
        },
        "indicators": extract_indicators(ascii_values, utf16_values),
        "entropy": {
            "overall": shannon_entropy(data),
            "byte_window": window_entropy_summary(data),
        },
        "chunks": chunk_summary(data),
    }
    result["format"] = analyze_format(data, filename)
    result["symbols"] = inspect_symbols(data, filename, result["format"])
    result["code"] = inspect_code(data, filename, result["format"], result["symbols"])
    result["rules"] = evaluate_rules(result)
    result["signatures"] = match_signature_set(
        data,
        filename=filename,
        format_info=result["format"],
    )
    return result


def case_id_for(path: Path, extraction: dict) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", path.name) or "file"
    return f"{safe}-{extraction['hashes']['sha256'][:12]}"


def build_manifest(path: Path, extraction: dict) -> dict:
    return {
        "case_id": case_id_for(path, extraction),
        "file_name": path.name,
        "source_path": str(path.resolve()),
        "size": extraction["size"],
        "sha256": extraction["hashes"]["sha256"],
        "created_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": "traceforge",
        "tool_version": __version__,
    }


def default_cases_root() -> Path:
    return Path(".traceforge") / "cases"


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def scan_file(path: Path, cases_root: Path | None = None) -> Path:
    """Scan one file and write a complete case folder. Returns the case dir."""
    path = Path(path)
    data = path.read_bytes()
    extraction = extract(data, path.name)
    manifest = build_manifest(path, extraction)
    report = {
        "manifest": manifest,
        "extraction": extraction,
        "score": score_extraction(extraction),
    }

    root = cases_root if cases_root is not None else default_cases_root()
    case_dir = Path(root) / manifest["case_id"]
    case_dir.mkdir(parents=True, exist_ok=True)

    _write_json(case_dir / "manifest.json", manifest)
    write_all_reports(case_dir, report)
    ensure_annotations(case_dir, report)
    graph = build_graph(report)
    _write_json(case_dir / "graph.json", graph)
    write_case_viewer(case_dir, report, graph)
    write_case_artifacts(case_dir, report, source_path=path)
    return case_dir


def iter_regular_files(directory: Path, recursive: bool = False) -> list[Path]:
    root = Path(directory)
    if recursive:
        return sorted(
            entry
            for entry in root.rglob("*")
            if entry.is_file() and ".traceforge" not in entry.relative_to(root).parts
        )
    return sorted(entry for entry in root.iterdir() if entry.is_file())


def scan_directory(
    directory: Path, recursive: bool = False, cases_root: Path | None = None
) -> list[Path]:
    """Scan regular files in a directory and return created case folders."""
    return [
        scan_file(path, cases_root=cases_root)
        for path in iter_regular_files(directory, recursive=recursive)
    ]


def load_report(case_dir: Path) -> dict:
    path = Path(case_dir) / "report.json"
    if not path.is_file():
        raise FileNotFoundError(f"{path} not found; run 'traceforge scan' first")
    return json.loads(path.read_text(encoding="utf-8"))


def regenerate_reports(case_dir: Path) -> list[Path]:
    """Rebuild report.html, summary.md and graph.json from stored report.json."""
    case_dir = Path(case_dir)
    report = load_report(case_dir)
    graph = build_graph(report)
    return [
        write_report_html(case_dir, report),
        write_summary_md(case_dir, report),
        _write_json(case_dir / "graph.json", graph),
        write_case_viewer(case_dir, report, graph),
    ]


def regenerate_exports(case_dir: Path) -> list[Path]:
    """Rebuild indicators.csv and indicators.json from stored report.json."""
    case_dir = Path(case_dir)
    report = load_report(case_dir)
    return write_indicator_exports(case_dir, report)


def regenerate_artifacts(
    case_dir: Path,
    source_path: Path | None = None,
    hexdump_limit: int = 8192,
) -> list[Path]:
    """Rebuild workbench artifact files for a stored case."""
    case_dir = Path(case_dir)
    report = load_report(case_dir)
    return write_case_artifacts(case_dir, report, source_path, hexdump_limit)


def regenerate_viewer(case_dir: Path) -> Path:
    """Rebuild viewer.html from report.json and graph.json data."""
    case_dir = Path(case_dir)
    report = load_report(case_dir)
    graph_path = case_dir / "graph.json"
    graph = (
        json.loads(graph_path.read_text(encoding="utf-8"))
        if graph_path.is_file()
        else build_graph(report)
    )
    return write_case_viewer(case_dir, report, graph)


def load_case_annotations(case_dir: Path) -> dict:
    """Load analyst annotations for a stored case."""
    return load_case_annotations_file(case_dir)


def annotate_case(
    case_dir: Path,
    *,
    status: str | None = None,
    add_tags: list[str] | tuple[str, ...] = (),
    remove_tags: list[str] | tuple[str, ...] = (),
    note_text: str | None = None,
    title: str | None = None,
    author: str | None = None,
) -> list[Path]:
    """Update case annotations and refresh the case viewer."""
    case_dir = Path(case_dir)
    update_paths = update_annotations(
        case_dir,
        status=status,
        add_tags=add_tags,
        remove_tags=remove_tags,
        note_text=note_text,
        title=title,
        author=author,
    )[1]
    report = load_report(case_dir)
    graph_path = case_dir / "graph.json"
    graph = (
        json.loads(graph_path.read_text(encoding="utf-8"))
        if graph_path.is_file()
        else build_graph(report)
    )
    viewer_path = write_case_viewer(case_dir, report, graph)
    return [*update_paths, viewer_path]


def write_case_index(cases_root: Path | None = None) -> Path:
    root = cases_root if cases_root is not None else default_cases_root()
    return workspace.write_case_index(root)


def build_case_database(
    cases_root: Path | None = None,
    db_path: Path | None = None,
) -> dict:
    """Build a SQLite database for a cases root."""
    root = cases_root if cases_root is not None else default_cases_root()
    return case_db.build_case_database(root, db_path)


def query_case_database(
    db_path: Path,
    *,
    format_kind: str | None = None,
    status: str | None = None,
    tag: str | None = None,
    rule_id: str | None = None,
    indicator: str | None = None,
    min_score: int | None = None,
    limit: int = case_db.DEFAULT_LIMIT,
) -> dict:
    """Query cases from a SQLite database."""
    return case_db.query_case_database(
        db_path,
        format_kind=format_kind,
        status=status,
        tag=tag,
        rule_id=rule_id,
        indicator=indicator,
        min_score=min_score,
        limit=limit,
    )


def write_workspace_browser(
    cases_root: Path | None = None,
    hunt_path: Path | None = None,
) -> list[Path]:
    """Write case_index.json and workspace.html for a cases root."""
    root = cases_root if cases_root is not None else default_cases_root()
    index_path = workspace.write_case_index(root)
    index = json.loads(index_path.read_text(encoding="utf-8"))
    viewer_path = write_workspace_viewer(root, index, _load_workspace_hunt(root, hunt_path))
    return [index_path, viewer_path]


def write_case_hunt(
    cases_root: Path | None = None,
    rules_path: Path | None = None,
    output_dir: Path | None = None,
) -> list[Path]:
    """Run a rule hunt across stored cases and write report files."""
    root = cases_root if cases_root is not None else default_cases_root()
    return write_hunt(root, rules_path, output_dir)


def validate_ruleset(path: Path | None = None) -> dict:
    """Validate built-in rules or a JSON rule file."""
    return ruleset_tools.validate_ruleset(path)


def describe_ruleset(path: Path | None = None) -> dict:
    """Return compact rule metadata and validation results."""
    return ruleset_tools.describe_ruleset(path)


def export_ruleset(output: Path, source: Path | None = None) -> Path:
    """Export built-in rules or normalize a JSON rule file."""
    return ruleset_tools.export_ruleset(output, source)


def schema_names() -> list[str]:
    """Return available JSON Schema names."""
    return schemas.schema_names()


def get_schema(name: str) -> dict:
    """Return a copy of a built-in JSON Schema."""
    return schemas.get_schema(name)


def dumps_schema(name: str) -> str:
    """Return a built-in JSON Schema as formatted JSON."""
    return schemas.dumps_schema(name)


def export_schema(name: str, output: Path) -> Path:
    """Write one built-in JSON Schema."""
    return schemas.export_schema(name, output)


def export_all_schemas(output_dir: Path) -> list[Path]:
    """Write every built-in JSON Schema to a directory."""
    return schemas.export_all_schemas(output_dir)


def create_case_bundle(case_dir: Path, output: Path | None = None) -> Path:
    """Write a portable zip bundle for a case directory."""
    return bundles.create_case_bundle(case_dir, output)


def build_bundle_manifest(case_dir: Path) -> dict:
    """Build a portable case bundle manifest."""
    return bundles.build_bundle_manifest(case_dir)


def verify_case_bundle(bundle: Path) -> dict:
    """Verify a portable case bundle."""
    return bundles.verify_case_bundle(bundle)


def import_case_bundle(
    bundle: Path,
    cases_root: Path | None = None,
    *,
    overwrite: bool = False,
) -> dict:
    """Import a verified case bundle into a cases root."""
    root = cases_root if cases_root is not None else default_cases_root()
    return bundles.import_case_bundle(bundle, root, overwrite=overwrite)


def build_cases_index(cases_root: Path | None = None) -> dict:
    root = cases_root if cases_root is not None else default_cases_root()
    return workspace.build_case_index(root)


def compare_cases(left_case_dir: Path, right_case_dir: Path) -> dict:
    return workspace.diff_cases(left_case_dir, right_case_dir)


def write_case_comparison(
    left_case_dir: Path, right_case_dir: Path, output_dir: Path | None = None
) -> list[Path]:
    return workspace.write_case_diff(left_case_dir, right_case_dir, output_dir)


def identify_file(path: Path) -> dict:
    """Return format metadata for one file without creating a case folder."""
    path = Path(path)
    return analyze_format(path.read_bytes(), path.name)


def evaluate_file_rules(path: Path, rules_path: Path | None = None) -> dict:
    """Evaluate built-in or external local rules for one file."""
    path = Path(path)
    extraction = extract(path.read_bytes(), path.name)
    return evaluate_rules(extraction, load_rules(rules_path))


def evaluate_file_signatures(path: Path, signatures_path: Path | None = None) -> dict:
    """Match built-in or external local signatures for one file."""
    return match_file_signatures(path, signatures_path)


def extract_file_payloads_to_dir(
    path: Path,
    output_dir: Path,
    *,
    sections: bool = True,
    resources: bool = True,
    overlay: bool = True,
) -> dict:
    """Extract selected sections, resources, and overlay bytes to a directory."""
    return extract_file_payloads(
        path,
        output_dir,
        sections=sections,
        resources=resources,
        overlay=overlay,
    )


def _load_workspace_hunt(cases_root: Path, hunt_path: Path | None) -> dict | None:
    path = Path(hunt_path) if hunt_path is not None else Path(cases_root) / "hunt" / "hunt.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
