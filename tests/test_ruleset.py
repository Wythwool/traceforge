"""Tests for rule set validation and export."""

import json

from traceforge import cli, core


def test_valid_ruleset_reports_rule_metadata(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom.marker",
                        "name": "Marker",
                        "level": "low",
                        "description": "Finds a marker string.",
                        "any": [{"contains": "marker"}, {"regex": "mark(er)?"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    payload = core.validate_ruleset(rules)

    assert payload["valid"] is True
    assert payload["rule_count"] == 1
    assert payload["rules"][0]["id"] == "custom.marker"
    assert payload["rules"][0]["condition_count"] == 2


def test_invalid_ruleset_collects_errors(tmp_path):
    rules = tmp_path / "bad-rules.json"
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "dup",
                        "name": "Broken",
                        "level": "medium",
                        "description": "Bad regex.",
                        "any": [{"regex": "["}],
                    },
                    {
                        "id": "dup",
                        "name": "Unknown",
                        "level": "urgent",
                        "description": "Unknown condition.",
                        "any": [{"unknown_key": "value"}],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    payload = core.validate_ruleset(rules)
    messages = " ".join(error["message"] for error in payload["errors"])

    assert payload["valid"] is False
    assert "id must be unique" in messages
    assert "regex does not compile" in messages
    assert "unknown condition key" in messages
    assert "level must be one of" in messages


def test_export_ruleset_writes_builtin_rules(tmp_path):
    output = tmp_path / "built-ins.json"

    path = core.export_ruleset(output)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert path == output
    assert "rules" in payload
    assert any(rule["id"] == "format.executable" for rule in payload["rules"])


def test_ruleset_cli_commands(tmp_path, capsys):
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "custom.hex",
                        "name": "MZ header",
                        "level": "info",
                        "description": "Checks for an MZ header.",
                        "any": [{"hex": "4d 5a"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert cli.main(["ruleset", "validate", str(rules)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True

    assert cli.main(["ruleset", "list", str(rules)]) == 0
    assert "custom.hex" in capsys.readouterr().out

    output = tmp_path / "exported-rules.json"
    assert cli.main(["ruleset", "export", str(rules), "-o", str(output)]) == 0
    assert output.is_file()


def test_ruleset_cli_returns_one_for_invalid_rules(tmp_path, capsys):
    rules = tmp_path / "bad.json"
    rules.write_text('{"rules":[{"id":"bad","any":[{"regex":"["}]}]}', encoding="utf-8")

    assert cli.main(["ruleset", "validate", str(rules)]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is False
