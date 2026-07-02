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

from traceforge import __version__, workspace
from traceforge.formats import analyze_format
from traceforge.graph import build_graph
from traceforge.reports import (
    write_all_reports,
    write_indicator_exports,
    write_report_html,
    write_summary_md,
)
from traceforge.rules import evaluate_rules, load_rules
from traceforge.score import score_extraction

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
    result["rules"] = evaluate_rules(result)
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
    _write_json(case_dir / "graph.json", build_graph(report))
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
    return [
        write_report_html(case_dir, report),
        write_summary_md(case_dir, report),
        _write_json(case_dir / "graph.json", build_graph(report)),
    ]


def regenerate_exports(case_dir: Path) -> list[Path]:
    """Rebuild indicators.csv and indicators.json from stored report.json."""
    case_dir = Path(case_dir)
    report = load_report(case_dir)
    return write_indicator_exports(case_dir, report)


def write_case_index(cases_root: Path | None = None) -> Path:
    root = cases_root if cases_root is not None else default_cases_root()
    return workspace.write_case_index(root)


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
