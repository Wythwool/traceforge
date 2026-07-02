"""SQLite case database for local workspaces."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from traceforge import workspace

SCHEMA_VERSION = 1
DEFAULT_LIMIT = 50
MAX_LIMIT = 1000


def default_database_path(cases_root: Path) -> Path:
    """Return the default database path for a cases root."""
    return Path(cases_root) / "traceforge.db"


def build_case_database(cases_root: Path, db_path: Path | None = None) -> dict:
    """Build a SQLite index from stored case folders."""
    root = Path(cases_root)
    destination = Path(db_path) if db_path is not None else default_database_path(root)
    destination.parent.mkdir(parents=True, exist_ok=True)

    index = workspace.build_case_index(root)
    with sqlite3.connect(destination) as db:
        db.execute("PRAGMA foreign_keys = ON")
        _create_schema(db)
        _replace_contents(db, index)

    return {
        "cases_root": str(root),
        "database": str(destination),
        "schema_version": SCHEMA_VERSION,
        "case_count": index["case_count"],
        "error_count": index["error_count"],
    }


def query_case_database(
    db_path: Path,
    *,
    format_kind: str | None = None,
    status: str | None = None,
    tag: str | None = None,
    rule_id: str | None = None,
    indicator: str | None = None,
    min_score: int | None = None,
    limit: int = DEFAULT_LIMIT,
) -> dict:
    """Query cases from a SQLite index with common analyst filters."""
    path = Path(db_path)
    capped_limit = min(max(int(limit), 1), MAX_LIMIT)
    sql, params = _query_sql(
        format_kind=format_kind,
        status=status,
        tag=tag,
        rule_id=rule_id,
        indicator=indicator,
        min_score=min_score,
        limit=capped_limit,
    )
    with sqlite3.connect(path) as db:
        db.row_factory = sqlite3.Row
        rows = [dict(row) for row in db.execute(sql, params).fetchall()]
    return {
        "database": str(path),
        "count": len(rows),
        "limit": capped_limit,
        "cases": rows,
    }


def _create_schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        DROP TABLE IF EXISTS tags;
        DROP TABLE IF EXISTS rule_matches;
        DROP TABLE IF EXISTS indicators;
        DROP TABLE IF EXISTS errors;
        DROP TABLE IF EXISTS cases;
        DROP TABLE IF EXISTS meta;

        CREATE TABLE meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE cases (
          case_id TEXT PRIMARY KEY,
          case_dir TEXT NOT NULL,
          file_name TEXT NOT NULL,
          source_path TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          size INTEGER NOT NULL,
          created_utc TEXT NOT NULL,
          format TEXT NOT NULL,
          format_confidence TEXT NOT NULL,
          score INTEGER NOT NULL,
          label TEXT NOT NULL,
          status TEXT NOT NULL,
          note_count INTEGER NOT NULL,
          latest_note_title TEXT NOT NULL,
          latest_note_utc TEXT NOT NULL,
          indicator_count INTEGER NOT NULL,
          rule_match_count INTEGER NOT NULL,
          string_count INTEGER NOT NULL,
          section_count INTEGER NOT NULL,
          resource_count INTEGER NOT NULL,
          import_count INTEGER NOT NULL,
          export_count INTEGER NOT NULL,
          symbol_count INTEGER NOT NULL,
          function_count INTEGER NOT NULL,
          xref_count INTEGER NOT NULL,
          embedded_artifact_count INTEGER NOT NULL
        );

        CREATE TABLE indicators (
          case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
          type TEXT NOT NULL,
          value TEXT NOT NULL,
          source TEXT NOT NULL
        );

        CREATE TABLE rule_matches (
          case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
          rule_id TEXT NOT NULL,
          level TEXT NOT NULL,
          name TEXT NOT NULL
        );

        CREATE TABLE tags (
          case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
          tag TEXT NOT NULL
        );

        CREATE TABLE errors (
          case_dir TEXT NOT NULL,
          error TEXT NOT NULL
        );

        CREATE INDEX idx_cases_format ON cases(format);
        CREATE INDEX idx_cases_status ON cases(status);
        CREATE INDEX idx_cases_score ON cases(score);
        CREATE INDEX idx_indicators_value ON indicators(value);
        CREATE INDEX idx_rules_rule_id ON rule_matches(rule_id);
        CREATE INDEX idx_tags_tag ON tags(tag);
        """
    )


def _replace_contents(db: sqlite3.Connection, index: dict) -> None:
    db.execute(
        "INSERT INTO meta(key, value) VALUES (?, ?)",
        ("schema_version", str(SCHEMA_VERSION)),
    )
    db.execute("INSERT INTO meta(key, value) VALUES (?, ?)", ("created_utc", index["created_utc"]))
    db.execute("INSERT INTO meta(key, value) VALUES (?, ?)", ("cases_root", index["cases_root"]))
    for case in index.get("cases", []):
        _insert_case(db, case)
        report = workspace.load_case_report(Path(case["case_dir"]))
        _insert_indicators(db, case["case_id"], report)
        _insert_rule_matches(db, case["case_id"], report)
        _insert_tags(db, case["case_id"], case.get("tags", []))
    for item in index.get("errors", []):
        db.execute(
            "INSERT INTO errors(case_dir, error) VALUES (?, ?)",
            (item.get("case_dir", ""), item.get("error", "")),
        )


def _insert_case(db: sqlite3.Connection, case: dict) -> None:
    db.execute(
        """
        INSERT INTO cases(
          case_id, case_dir, file_name, source_path, sha256, size, created_utc,
          format, format_confidence, score, label, status, note_count,
          latest_note_title, latest_note_utc, indicator_count, rule_match_count,
          string_count, section_count, resource_count, import_count, export_count,
          symbol_count, function_count, xref_count, embedded_artifact_count
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case.get("case_id", ""),
            case.get("case_dir", ""),
            case.get("file_name", ""),
            case.get("source_path", ""),
            case.get("sha256", ""),
            int(case.get("size", 0)),
            case.get("created_utc", ""),
            case.get("format", "raw"),
            case.get("format_confidence", "low"),
            int(case.get("score", 0)),
            case.get("label", "low"),
            case.get("status", "new"),
            int(case.get("note_count", 0)),
            case.get("latest_note_title", ""),
            case.get("latest_note_utc", ""),
            int(case.get("indicator_count", 0)),
            int(case.get("rule_match_count", 0)),
            int(case.get("string_count", 0)),
            int(case.get("section_count", 0)),
            int(case.get("resource_count", 0)),
            int(case.get("import_count", 0)),
            int(case.get("export_count", 0)),
            int(case.get("symbol_count", 0)),
            int(case.get("function_count", 0)),
            int(case.get("xref_count", 0)),
            int(case.get("embedded_artifact_count", 0)),
        ),
    )


def _insert_indicators(db: sqlite3.Connection, case_id: str, report: dict) -> None:
    rows = [
        (
            case_id,
            item.get("type", ""),
            item.get("value", ""),
            item.get("source", ""),
        )
        for item in report.get("extraction", {}).get("indicators", [])
    ]
    db.executemany(
        "INSERT INTO indicators(case_id, type, value, source) VALUES (?, ?, ?, ?)",
        rows,
    )


def _insert_rule_matches(db: sqlite3.Connection, case_id: str, report: dict) -> None:
    rows = [
        (
            case_id,
            item.get("id", ""),
            item.get("level", ""),
            item.get("name", ""),
        )
        for item in report.get("extraction", {}).get("rules", {}).get("matches", [])
    ]
    db.executemany(
        "INSERT INTO rule_matches(case_id, rule_id, level, name) VALUES (?, ?, ?, ?)",
        rows,
    )


def _insert_tags(db: sqlite3.Connection, case_id: str, tags: list[str]) -> None:
    db.executemany(
        "INSERT INTO tags(case_id, tag) VALUES (?, ?)",
        [(case_id, tag) for tag in tags],
    )


def _query_sql(
    *,
    format_kind: str | None,
    status: str | None,
    tag: str | None,
    rule_id: str | None,
    indicator: str | None,
    min_score: int | None,
    limit: int,
) -> tuple[str, list[Any]]:
    joins = []
    clauses = []
    params: list[Any] = []
    if tag:
        joins.append("JOIN tags t ON t.case_id = c.case_id")
        clauses.append("t.tag = ?")
        params.append(tag)
    if rule_id:
        joins.append("JOIN rule_matches r ON r.case_id = c.case_id")
        clauses.append("r.rule_id = ?")
        params.append(rule_id)
    if indicator:
        joins.append("JOIN indicators i ON i.case_id = c.case_id")
        clauses.append("LOWER(i.value) LIKE ?")
        params.append(f"%{indicator.lower()}%")
    if format_kind:
        clauses.append("c.format = ?")
        params.append(format_kind)
    if status:
        clauses.append("c.status = ?")
        params.append(status)
    if min_score is not None:
        clauses.append("c.score >= ?")
        params.append(int(min_score))

    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    sql = f"""
        SELECT DISTINCT
          c.case_id, c.file_name, c.source_path, c.sha256, c.size, c.created_utc,
          c.format, c.score, c.label, c.status, c.indicator_count,
          c.rule_match_count, c.string_count, c.import_count, c.export_count,
          c.function_count, c.xref_count, c.case_dir
        FROM cases c
        {' '.join(joins)}
        {where}
        ORDER BY c.score DESC, c.created_utc DESC, c.case_id ASC
        LIMIT ?
    """
    params.append(limit)
    return sql, params


def dumps(payload: dict) -> str:
    """Render stable JSON for CLI output."""
    return json.dumps(payload, indent=2) + "\n"
