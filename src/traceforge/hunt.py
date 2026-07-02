"""Workspace rule hunting across stored cases."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

from traceforge.rules import evaluate_rules, load_rules
from traceforge.workspace import case_directories, load_case_report, summarize_case

HUNT_JSON_NAME = "hunt.json"
HUNT_CSV_NAME = "hunt.csv"
HUNT_MARKDOWN_NAME = "hunt.md"

_LEVEL_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def run_hunt(cases_root: Path, rules_path: Path | None = None) -> dict:
    """Evaluate a rule set against every stored case in a cases root."""
    root = Path(cases_root)
    rules = load_rules(rules_path)
    cases = []
    matches = []
    errors = []
    for case_dir in case_directories(root):
        try:
            report = load_case_report(case_dir)
            summary = summarize_case(case_dir, report)
            result = evaluate_rules(report.get("extraction", {}), rules)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append({"case_dir": str(case_dir), "error": str(exc)})
            continue

        case_match_count = len(result.get("matches", []))
        cases.append(
            {
                "case_id": summary["case_id"],
                "case_dir": summary["case_dir"],
                "file_name": summary["file_name"],
                "sha256": summary["sha256"],
                "status": summary.get("status", "new"),
                "tags": summary.get("tags", []),
                "score": summary.get("score", 0),
                "match_count": case_match_count,
            }
        )
        for match in result.get("matches", []):
            matches.append(_match_row(summary, match))

    matches.sort(key=_match_sort_key)
    return {
        "created_utc": _utc_now(),
        "cases_root": str(root),
        "rules_path": str(rules_path) if rules_path is not None else "built-in",
        "rule_count": len(rules),
        "case_count": len(cases),
        "matched_case_count": len({item["case_id"] for item in matches}),
        "match_count": len(matches),
        "error_count": len(errors),
        "cases": sorted(cases, key=lambda item: item["case_id"]),
        "matches": matches,
        "errors": errors,
    }


def write_hunt(
    cases_root: Path,
    rules_path: Path | None = None,
    output_dir: Path | None = None,
) -> list[Path]:
    """Write JSON, CSV, and Markdown hunt output."""
    payload = run_hunt(cases_root, rules_path)
    target = Path(output_dir) if output_dir is not None else Path(cases_root) / "hunt"
    target.mkdir(parents=True, exist_ok=True)
    json_path = target / HUNT_JSON_NAME
    csv_path = target / HUNT_CSV_NAME
    md_path = target / HUNT_MARKDOWN_NAME
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    _write_hunt_csv(csv_path, payload)
    md_path.write_text(render_hunt_markdown(payload), encoding="utf-8")
    return [json_path, csv_path, md_path]


def render_hunt_markdown(payload: dict) -> str:
    """Render a compact hunt report."""
    lines = [
        "# Hunt results",
        "",
        f"- Cases root: `{_tick(payload.get('cases_root', ''))}`",
        f"- Rules: `{_tick(payload.get('rules_path', ''))}`",
        f"- Rule count: `{payload.get('rule_count', 0)}`",
        f"- Cases scanned: `{payload.get('case_count', 0)}`",
        f"- Matched cases: `{payload.get('matched_case_count', 0)}`",
        f"- Rule matches: `{payload.get('match_count', 0)}`",
        f"- Errors: `{payload.get('error_count', 0)}`",
        "",
        "## Matches",
        "",
    ]
    matches = payload.get("matches", [])
    if not matches:
        lines.append("No rule matches.")
    for item in matches:
        evidence = "; ".join(item.get("evidence", [])[:3])
        lines.extend(
            [
                f"### {_plain(item.get('rule_id', 'rule'))}",
                "",
                f"- Case: `{_tick(item.get('case_id', ''))}`",
                f"- File: `{_tick(item.get('file_name', ''))}`",
                f"- Level: `{_tick(item.get('level', 'info'))}`",
                f"- Rule: `{_tick(item.get('name', ''))}`",
                f"- Evidence: `{_tick(evidence)}`",
                "",
            ]
        )
    if payload.get("errors"):
        lines.extend(["## Errors", ""])
        for error in payload["errors"]:
            case_dir = _tick(error.get("case_dir", ""))
            detail = _plain(error.get("error", ""))
            lines.append(f"- `{case_dir}`: {detail}")
    return "\n".join(lines).rstrip() + "\n"


def _match_row(summary: dict, match: dict) -> dict:
    return {
        "case_id": summary["case_id"],
        "case_dir": summary["case_dir"],
        "file_name": summary["file_name"],
        "sha256": summary["sha256"],
        "status": summary.get("status", "new"),
        "tags": summary.get("tags", []),
        "score": summary.get("score", 0),
        "rule_id": match.get("id", "unnamed"),
        "name": match.get("name", match.get("id", "unnamed")),
        "level": match.get("level", "info"),
        "description": match.get("description", ""),
        "evidence": match.get("evidence", []),
    }


def _write_hunt_csv(path: Path, payload: dict) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "case_id",
                "file_name",
                "sha256",
                "status",
                "tags",
                "score",
                "rule_id",
                "level",
                "name",
                "evidence",
            ]
        )
        for item in payload.get("matches", []):
            writer.writerow(
                [
                    item.get("case_id", ""),
                    item.get("file_name", ""),
                    item.get("sha256", ""),
                    item.get("status", ""),
                    ", ".join(item.get("tags", [])),
                    item.get("score", ""),
                    item.get("rule_id", ""),
                    item.get("level", ""),
                    item.get("name", ""),
                    "; ".join(item.get("evidence", [])),
                ]
            )
    return path


def _match_sort_key(item: dict) -> tuple[str, int, str]:
    level = str(item.get("level", "info")).lower()
    return (
        str(item.get("case_id", "")),
        _LEVEL_ORDER.get(level, 99),
        str(item.get("rule_id", "")),
    )


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tick(value: object) -> str:
    return str(value).replace("`", "'")


def _plain(value: object) -> str:
    return str(value).replace("\r\n", "\n").replace("\r", "\n").strip()
