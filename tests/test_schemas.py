"""Tests for built-in JSON Schemas."""

import json

from traceforge import cli, core

EXPECTED_SCHEMAS = {
    "case-bundle",
    "case-index",
    "extract-manifest",
    "hunt",
    "report",
    "ruleset",
}


def test_schema_names_are_stable():
    assert set(core.schema_names()) == EXPECTED_SCHEMAS
    assert core.schema_names() == sorted(EXPECTED_SCHEMAS)


def test_schema_documents_are_json_schema_objects():
    for name in core.schema_names():
        payload = core.get_schema(name)

        assert payload["$schema"].startswith("https://json-schema.org/")
        assert payload["$id"].endswith(f"/{name}.schema.json")
        assert payload.get("type") == "object" or "oneOf" in payload
        assert payload.get("required") or payload.get("oneOf")
        assert "$defs" in payload
        json.dumps(payload)


def test_get_schema_returns_a_copy():
    payload = core.get_schema("report")
    payload["title"] = "Changed"

    assert core.get_schema("report")["title"] == "TraceForge case report"


def test_export_schema_writes_named_file(tmp_path):
    output = tmp_path / "schema-output"

    path = core.export_schema("report", output)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert path == output / "report.schema.json"
    assert payload["title"] == "TraceForge case report"


def test_export_all_schemas_writes_every_schema(tmp_path):
    paths = core.export_all_schemas(tmp_path / "schemas")

    names = {path.name for path in paths}
    assert names == {f"{name}.schema.json" for name in EXPECTED_SCHEMAS}


def test_schema_cli_commands(tmp_path, capsys):
    assert cli.main(["schema", "list"]) == 0
    assert "report" in capsys.readouterr().out

    assert cli.main(["schema", "show", "report"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["title"] == "TraceForge case report"

    output = tmp_path / "schemas"
    assert cli.main(["schema", "export-all", "-o", str(output)]) == 0
    assert (output / "report.schema.json").is_file()
