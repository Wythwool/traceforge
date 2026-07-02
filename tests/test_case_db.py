"""Tests for the SQLite case database."""

import json
import sqlite3

from traceforge import cli, core
from traceforge.case_db import build_case_database, query_case_database


def test_build_case_database_indexes_cases_indicators_rules_and_tags(tmp_path):
    cases_root = tmp_path / "cases"
    one = tmp_path / "one.bin"
    two = tmp_path / "two.bin"
    one.write_bytes(b"alpha marker http://one.example.com 10.1.1.1\n")
    two.write_bytes(b"beta marker http://two.example.net 10.2.2.2\n")

    one_case = core.scan_file(one, cases_root=cases_root)
    core.scan_file(two, cases_root=cases_root)
    core.annotate_case(one_case, status="triage", add_tags=["network"])
    db_path = tmp_path / "cases.db"

    summary = build_case_database(cases_root, db_path)

    assert summary["case_count"] == 2
    assert summary["error_count"] == 0
    assert db_path.is_file()
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] >= 4
        assert db.execute("SELECT COUNT(*) FROM rule_matches").fetchone()[0] >= 2
        assert db.execute("SELECT tag FROM tags").fetchone()[0] == "network"


def test_query_case_database_filters_by_indicator_tag_and_rule(tmp_path):
    cases_root = tmp_path / "cases"
    one = tmp_path / "one.bin"
    two = tmp_path / "two.bin"
    one.write_bytes(b"alpha http://one.example.com 10.1.1.1\n")
    two.write_bytes(b"beta http://two.example.net 10.2.2.2\n")
    one_case = core.scan_file(one, cases_root=cases_root)
    core.scan_file(two, cases_root=cases_root)
    core.annotate_case(one_case, status="triage", add_tags=["network"])
    db_path = tmp_path / "cases.db"
    build_case_database(cases_root, db_path)

    by_indicator = query_case_database(db_path, indicator="one.example.com")
    by_tag = query_case_database(db_path, tag="network")
    by_rule = query_case_database(db_path, rule_id="indicators.network")

    assert by_indicator["count"] == 1
    assert by_indicator["cases"][0]["file_name"] == "one.bin"
    assert by_tag["count"] == 1
    assert by_tag["cases"][0]["status"] == "triage"
    assert by_rule["count"] == 2


def test_db_cli_builds_and_queries_json(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    left = tmp_path / "left.bin"
    right = tmp_path / "right.bin"
    left.write_bytes(b"left http://left.example.com\n")
    right.write_bytes(b"right http://right.example.net\n")

    assert cli.main(["scan", str(left)]) == 0
    assert cli.main(["scan", str(right)]) == 0
    cases_root = tmp_path / ".traceforge" / "cases"
    db_path = tmp_path / "traceforge.db"

    assert cli.main(["db", "build", str(cases_root), "-o", str(db_path)]) == 0
    assert "indexed 2 case(s)" in capsys.readouterr().out
    assert cli.main(["db", "query", str(db_path), "--indicator", "right.example", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["count"] == 1
    assert payload["cases"][0]["file_name"] == "right.bin"
