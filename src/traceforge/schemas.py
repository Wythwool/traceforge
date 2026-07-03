"""JSON Schemas for TraceForge exchange files."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

SCHEMA_DRAFT_URI = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_BASE_ID = "https://github.com/Wythwool/traceforge/schemas"

_COMMON_DEFS: dict[str, Any] = {
    "utcTimestamp": {
        "type": "string",
        "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
    },
    "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
    "path": {"type": "string", "minLength": 1},
    "count": {"type": "integer", "minimum": 0},
    "stringList": {"type": "array", "items": {"type": "string"}},
    "hashes": {
        "type": "object",
        "required": ["sha256", "sha1", "md5"],
        "properties": {
            "sha256": {"$ref": "#/$defs/sha256"},
            "sha1": {"type": "string", "pattern": "^[a-f0-9]{40}$"},
            "md5": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
        },
        "additionalProperties": True,
    },
    "error": {
        "type": "object",
        "required": ["error"],
        "properties": {
            "case_dir": {"type": "string"},
            "error": {"type": "string"},
        },
        "additionalProperties": True,
    },
}


def _document(name: str, title: str, description: str, schema: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "$schema": SCHEMA_DRAFT_URI,
        "$id": f"{SCHEMA_BASE_ID}/{name}.schema.json",
        "title": title,
        "description": description,
        "$defs": copy.deepcopy(_COMMON_DEFS),
    }
    payload.update(schema)
    return payload


SCHEMAS: dict[str, dict[str, Any]] = {
    "case-bundle": _document(
        "case-bundle",
        "TraceForge case bundle manifest",
        "Portable case bundle manifest stored as bundle_manifest.json.",
        {
            "type": "object",
            "required": [
                "kind",
                "schema_version",
                "created_utc",
                "tool",
                "tool_version",
                "case_id",
                "file_count",
                "total_size",
                "files",
            ],
            "properties": {
                "kind": {"const": "traceforge.case-bundle"},
                "schema_version": {"const": 1},
                "created_utc": {"$ref": "#/$defs/utcTimestamp"},
                "tool": {"const": "traceforge"},
                "tool_version": {"type": "string"},
                "case_id": {"type": "string", "minLength": 1},
                "file_count": {"$ref": "#/$defs/count"},
                "total_size": {"$ref": "#/$defs/count"},
                "files": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/bundledFile"},
                },
            },
            "$defs": {
                **copy.deepcopy(_COMMON_DEFS),
                "bundledFile": {
                    "type": "object",
                    "required": ["path", "size", "sha256"],
                    "properties": {
                        "path": {
                            "type": "string",
                            "minLength": 1,
                            "not": {"pattern": r"(^/|^[A-Za-z]:|(^|/)\.\.(/|$))"},
                        },
                        "size": {"$ref": "#/$defs/count"},
                        "sha256": {"$ref": "#/$defs/sha256"},
                    },
                    "additionalProperties": False,
                },
            },
            "additionalProperties": False,
        },
    ),
    "case-index": _document(
        "case-index",
        "TraceForge case index",
        "Compact case index written by traceforge index and traceforge workspace.",
        {
            "type": "object",
            "required": [
                "created_utc",
                "cases_root",
                "case_count",
                "error_count",
                "cases",
                "errors",
            ],
            "properties": {
                "created_utc": {"$ref": "#/$defs/utcTimestamp"},
                "cases_root": {"type": "string"},
                "case_count": {"$ref": "#/$defs/count"},
                "error_count": {"$ref": "#/$defs/count"},
                "cases": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/caseSummary"},
                },
                "errors": {"type": "array", "items": {"$ref": "#/$defs/error"}},
            },
            "$defs": {
                **copy.deepcopy(_COMMON_DEFS),
                "caseSummary": {
                    "type": "object",
                    "required": [
                        "case_id",
                        "case_dir",
                        "file_name",
                        "sha256",
                        "size",
                        "format",
                        "score",
                        "status",
                        "indicator_count",
                        "rule_match_count",
                    ],
                    "properties": {
                        "case_id": {"type": "string", "minLength": 1},
                        "case_dir": {"type": "string"},
                        "file_name": {"type": "string"},
                        "source_path": {"type": "string"},
                        "sha256": {"$ref": "#/$defs/sha256"},
                        "size": {"$ref": "#/$defs/count"},
                        "created_utc": {"type": "string"},
                        "format": {"type": "string"},
                        "format_confidence": {"type": "string"},
                        "score": {"type": "integer", "minimum": 0, "maximum": 100},
                        "label": {"type": "string"},
                        "status": {"type": "string"},
                        "tags": {"$ref": "#/$defs/stringList"},
                        "note_count": {"$ref": "#/$defs/count"},
                        "indicator_count": {"$ref": "#/$defs/count"},
                        "rule_match_count": {"$ref": "#/$defs/count"},
                        "string_count": {"$ref": "#/$defs/count"},
                        "section_count": {"$ref": "#/$defs/count"},
                        "resource_count": {"$ref": "#/$defs/count"},
                        "debug_entry_count": {"$ref": "#/$defs/count"},
                        "import_count": {"$ref": "#/$defs/count"},
                        "export_count": {"$ref": "#/$defs/count"},
                        "function_count": {"$ref": "#/$defs/count"},
                        "basic_block_count": {"$ref": "#/$defs/count"},
                        "xref_count": {"$ref": "#/$defs/count"},
                    },
                    "additionalProperties": True,
                },
            },
            "additionalProperties": True,
        },
    ),
    "extract-manifest": _document(
        "extract-manifest",
        "TraceForge extract manifest",
        "Payload manifest written by traceforge extract.",
        {
            "type": "object",
            "required": ["source_path", "file_name", "format", "output_dir", "count", "records"],
            "properties": {
                "source_path": {"type": "string"},
                "file_name": {"type": "string"},
                "format": {"type": "string"},
                "output_dir": {"type": "string"},
                "count": {"$ref": "#/$defs/count"},
                "records": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/extractedPayload"},
                },
            },
            "$defs": {
                **copy.deepcopy(_COMMON_DEFS),
                "extractedPayload": {
                    "type": "object",
                    "required": [
                        "kind",
                        "index",
                        "label",
                        "offset",
                        "size",
                        "requested_size",
                        "sha256",
                        "path",
                        "metadata",
                    ],
                    "properties": {
                        "kind": {"enum": ["section", "resource", "overlay"]},
                        "index": {"$ref": "#/$defs/count"},
                        "label": {"type": "string"},
                        "offset": {"$ref": "#/$defs/count"},
                        "size": {"type": "integer", "minimum": 1},
                        "requested_size": {"type": "integer", "minimum": 1},
                        "sha256": {"$ref": "#/$defs/sha256"},
                        "path": {"type": "string", "minLength": 1},
                        "metadata": {"type": "object", "additionalProperties": True},
                    },
                    "additionalProperties": True,
                },
            },
            "additionalProperties": True,
        },
    ),
    "hunt": _document(
        "hunt",
        "TraceForge hunt report",
        "Workspace rule-hunt result written by traceforge hunt.",
        {
            "type": "object",
            "required": [
                "created_utc",
                "cases_root",
                "rules_path",
                "rule_count",
                "case_count",
                "matched_case_count",
                "match_count",
                "error_count",
                "cases",
                "matches",
                "errors",
            ],
            "properties": {
                "created_utc": {"$ref": "#/$defs/utcTimestamp"},
                "cases_root": {"type": "string"},
                "rules_path": {"type": "string"},
                "rule_count": {"$ref": "#/$defs/count"},
                "case_count": {"$ref": "#/$defs/count"},
                "matched_case_count": {"$ref": "#/$defs/count"},
                "match_count": {"$ref": "#/$defs/count"},
                "error_count": {"$ref": "#/$defs/count"},
                "cases": {"type": "array", "items": {"$ref": "#/$defs/huntCase"}},
                "matches": {"type": "array", "items": {"$ref": "#/$defs/huntMatch"}},
                "errors": {"type": "array", "items": {"$ref": "#/$defs/error"}},
            },
            "$defs": {
                **copy.deepcopy(_COMMON_DEFS),
                "huntCase": {
                    "type": "object",
                    "required": [
                        "case_id",
                        "case_dir",
                        "file_name",
                        "sha256",
                        "status",
                        "tags",
                        "score",
                        "match_count",
                    ],
                    "properties": {
                        "case_id": {"type": "string"},
                        "case_dir": {"type": "string"},
                        "file_name": {"type": "string"},
                        "sha256": {"$ref": "#/$defs/sha256"},
                        "status": {"type": "string"},
                        "tags": {"$ref": "#/$defs/stringList"},
                        "score": {"type": "integer", "minimum": 0, "maximum": 100},
                        "match_count": {"$ref": "#/$defs/count"},
                    },
                    "additionalProperties": True,
                },
                "huntMatch": {
                    "type": "object",
                    "required": [
                        "case_id",
                        "case_dir",
                        "file_name",
                        "sha256",
                        "rule_id",
                        "level",
                        "name",
                        "evidence",
                    ],
                    "properties": {
                        "case_id": {"type": "string"},
                        "case_dir": {"type": "string"},
                        "file_name": {"type": "string"},
                        "sha256": {"$ref": "#/$defs/sha256"},
                        "status": {"type": "string"},
                        "tags": {"$ref": "#/$defs/stringList"},
                        "score": {"type": "integer", "minimum": 0, "maximum": 100},
                        "rule_id": {"type": "string"},
                        "name": {"type": "string"},
                        "level": {
                            "enum": ["info", "low", "medium", "high", "critical"],
                        },
                        "description": {"type": "string"},
                        "evidence": {"$ref": "#/$defs/stringList"},
                    },
                    "additionalProperties": True,
                },
            },
            "additionalProperties": True,
        },
    ),
    "report": _document(
        "report",
        "TraceForge case report",
        "Full structured case report written as report.json.",
        {
            "type": "object",
            "required": ["manifest", "extraction", "score"],
            "properties": {
                "manifest": {"$ref": "#/$defs/manifest"},
                "extraction": {"$ref": "#/$defs/extraction"},
                "score": {"$ref": "#/$defs/score"},
            },
            "$defs": {
                **copy.deepcopy(_COMMON_DEFS),
                "manifest": {
                    "type": "object",
                    "required": [
                        "case_id",
                        "file_name",
                        "source_path",
                        "size",
                        "sha256",
                        "created_utc",
                        "tool",
                        "tool_version",
                    ],
                    "properties": {
                        "case_id": {"type": "string", "minLength": 1},
                        "file_name": {"type": "string"},
                        "source_path": {"type": "string"},
                        "size": {"$ref": "#/$defs/count"},
                        "sha256": {"$ref": "#/$defs/sha256"},
                        "created_utc": {"$ref": "#/$defs/utcTimestamp"},
                        "tool": {"const": "traceforge"},
                        "tool_version": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
                "extraction": {
                    "type": "object",
                    "required": [
                        "size",
                        "hashes",
                        "first_bytes_hex",
                        "strings",
                        "indicators",
                        "entropy",
                        "chunks",
                        "format",
                        "rules",
                    ],
                    "properties": {
                        "size": {"$ref": "#/$defs/count"},
                        "hashes": {"$ref": "#/$defs/hashes"},
                        "first_bytes_hex": {"type": "string", "pattern": "^[a-f0-9]*$"},
                        "strings": {"$ref": "#/$defs/stringExtraction"},
                        "indicators": {
                            "type": "array",
                            "items": {"$ref": "#/$defs/indicator"},
                        },
                        "entropy": {"$ref": "#/$defs/entropy"},
                        "chunks": {"$ref": "#/$defs/chunks"},
                        "format": {"$ref": "#/$defs/formatInfo"},
                        "symbols": {"type": "object", "additionalProperties": True},
                        "code": {"type": "object", "additionalProperties": True},
                        "rules": {"$ref": "#/$defs/ruleResult"},
                        "signatures": {"$ref": "#/$defs/signatureResult"},
                        "capabilities": {"$ref": "#/$defs/capabilityResult"},
                    },
                    "additionalProperties": True,
                },
                "stringExtraction": {
                    "type": "object",
                    "required": ["min_length", "ascii", "utf16le"],
                    "properties": {
                        "min_length": {"type": "integer", "minimum": 1},
                        "ascii": {"$ref": "#/$defs/stringBucket"},
                        "utf16le": {"$ref": "#/$defs/stringBucket"},
                    },
                    "additionalProperties": True,
                },
                "stringBucket": {
                    "type": "object",
                    "required": ["total", "values"],
                    "properties": {
                        "total": {"$ref": "#/$defs/count"},
                        "values": {"$ref": "#/$defs/stringList"},
                    },
                    "additionalProperties": True,
                },
                "indicator": {
                    "type": "object",
                    "required": ["type", "value", "source"],
                    "properties": {
                        "type": {"type": "string"},
                        "value": {"type": "string"},
                        "source": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
                "entropy": {
                    "type": "object",
                    "required": ["overall", "byte_window"],
                    "properties": {
                        "overall": {"type": "number", "minimum": 0, "maximum": 8},
                        "byte_window": {"type": "object", "additionalProperties": True},
                    },
                    "additionalProperties": True,
                },
                "chunks": {
                    "type": "object",
                    "required": ["chunk_size", "total", "truncated", "records"],
                    "properties": {
                        "chunk_size": {"type": "integer", "minimum": 1},
                        "total": {"$ref": "#/$defs/count"},
                        "truncated": {"type": "boolean"},
                        "records": {
                            "type": "array",
                            "items": {"type": "object", "additionalProperties": True},
                        },
                    },
                    "additionalProperties": True,
                },
                "formatInfo": {
                    "type": "object",
                    "required": ["kind", "confidence"],
                    "properties": {
                        "kind": {"type": "string"},
                        "confidence": {"type": "string"},
                        "details": {"type": "object", "additionalProperties": True},
                        "embedded": {"type": "array"},
                    },
                    "additionalProperties": True,
                },
                "ruleResult": {
                    "type": "object",
                    "required": ["match_count", "matches"],
                    "properties": {
                        "match_count": {"$ref": "#/$defs/count"},
                        "matches": {
                            "type": "array",
                            "items": {"type": "object", "additionalProperties": True},
                        },
                    },
                    "additionalProperties": True,
                },
                "signatureResult": {
                    "type": "object",
                    "required": ["engine", "signature_count", "match_count", "matches"],
                    "properties": {
                        "engine": {"const": "traceforge-signatures"},
                        "signature_count": {"$ref": "#/$defs/count"},
                        "match_count": {"$ref": "#/$defs/count"},
                        "truncated": {"type": "boolean"},
                        "matches": {
                            "type": "array",
                            "items": {"type": "object", "additionalProperties": True},
                        },
                    },
                    "additionalProperties": True,
                },
                "capabilityResult": {
                    "type": "object",
                    "required": [
                        "engine",
                        "category_count",
                        "match_count",
                        "summary",
                        "categories",
                    ],
                    "properties": {
                        "engine": {"const": "traceforge-capabilities"},
                        "format": {"type": "string"},
                        "category_count": {"$ref": "#/$defs/count"},
                        "match_count": {"$ref": "#/$defs/count"},
                        "summary": {"$ref": "#/$defs/stringList"},
                        "categories": {
                            "type": "array",
                            "items": {"type": "object", "additionalProperties": True},
                        },
                    },
                    "additionalProperties": True,
                },
                "score": {
                    "type": "object",
                    "required": ["score", "max_score", "label", "reasons"],
                    "properties": {
                        "score": {"type": "integer", "minimum": 0, "maximum": 100},
                        "max_score": {"type": "integer", "minimum": 1},
                        "label": {"type": "string"},
                        "reasons": {"$ref": "#/$defs/stringList"},
                    },
                    "additionalProperties": True,
                },
            },
            "additionalProperties": True,
        },
    ),
    "capabilities": _document(
        "capabilities",
        "TraceForge capability report",
        "Static capability groups written by traceforge capabilities.",
        {
            "type": "object",
            "required": [
                "engine",
                "format",
                "category_count",
                "match_count",
                "summary",
                "categories",
            ],
            "properties": {
                "engine": {"const": "traceforge-capabilities"},
                "file_name": {"type": "string"},
                "size": {"$ref": "#/$defs/count"},
                "format": {"type": "string"},
                "category_count": {"$ref": "#/$defs/count"},
                "match_count": {"$ref": "#/$defs/count"},
                "summary": {"$ref": "#/$defs/stringList"},
                "categories": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/capabilityCategory"},
                },
            },
            "$defs": {
                **copy.deepcopy(_COMMON_DEFS),
                "capabilityCategory": {
                    "type": "object",
                    "required": [
                        "id",
                        "name",
                        "description",
                        "confidence",
                        "evidence_count",
                        "evidence",
                    ],
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"},
                        "description": {"type": "string"},
                        "confidence": {"enum": ["low", "medium", "high"]},
                        "evidence_count": {"$ref": "#/$defs/count"},
                        "evidence": {
                            "type": "array",
                            "items": {"$ref": "#/$defs/capabilityEvidence"},
                        },
                    },
                    "additionalProperties": True,
                },
                "capabilityEvidence": {
                    "type": "object",
                    "required": ["source", "kind", "value", "reason"],
                    "properties": {
                        "source": {"type": "string"},
                        "kind": {"type": "string"},
                        "value": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            },
            "additionalProperties": True,
        },
    ),
    "signature-set": _document(
        "signature-set",
        "TraceForge signature set",
        "External JSON signature set accepted by traceforge signatures.",
        {
            "type": "object",
            "required": ["signatures"],
            "properties": {
                "signatures": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"$ref": "#/$defs/signature"},
                }
            },
            "$defs": {
                **copy.deepcopy(_COMMON_DEFS),
                "signature": {
                    "type": "object",
                    "required": ["id", "patterns"],
                    "properties": {
                        "id": {"type": "string", "minLength": 1},
                        "name": {"type": "string"},
                        "level": {
                            "enum": ["info", "low", "medium", "high", "critical"],
                            "default": "info",
                        },
                        "description": {"type": "string"},
                        "condition": {"enum": ["any", "all"], "default": "any"},
                        "min_patterns": {"type": "integer", "minimum": 1},
                        "patterns": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"$ref": "#/$defs/signaturePattern"},
                        },
                    },
                    "additionalProperties": False,
                },
                "signaturePattern": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "text": {"type": "string", "minLength": 1},
                        "hex": {"type": "string", "minLength": 1},
                        "regex": {"type": "string", "minLength": 1},
                        "ascii": {"type": "boolean"},
                        "wide": {"type": "boolean"},
                        "nocase": {"type": "boolean"},
                        "offset": {"type": "integer", "minimum": 0},
                        "offsets": {
                            "type": "array",
                            "items": {"type": "integer", "minimum": 0},
                        },
                        "max_matches": {"type": "integer", "minimum": 1},
                    },
                    "oneOf": [
                        {"required": ["text"]},
                        {"required": ["hex"]},
                        {"required": ["regex"]},
                    ],
                    "additionalProperties": False,
                },
            },
            "additionalProperties": False,
        },
    ),
    "ruleset": _document(
        "ruleset",
        "TraceForge rule set",
        "External JSON rule set accepted by traceforge rules and traceforge hunt.",
        {
            "oneOf": [
                {"$ref": "#/$defs/rulesetDocument"},
                {
                    "type": "array",
                    "minItems": 1,
                    "items": {"$ref": "#/$defs/rule"},
                },
            ],
            "$defs": {
                **copy.deepcopy(_COMMON_DEFS),
                "rulesetDocument": {
                    "type": "object",
                    "required": ["rules"],
                    "properties": {
                        "rules": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"$ref": "#/$defs/rule"},
                        }
                    },
                    "additionalProperties": False,
                },
                "rule": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": {"type": "string", "minLength": 1},
                        "name": {"type": "string"},
                        "level": {
                            "enum": ["info", "low", "medium", "high", "critical"],
                            "default": "info",
                        },
                        "description": {"type": "string"},
                        "any": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"$ref": "#/$defs/condition"},
                        },
                        "all": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"$ref": "#/$defs/condition"},
                        },
                    },
                    "oneOf": [
                        {"required": ["any"], "not": {"required": ["all"]}},
                        {"required": ["all"], "not": {"required": ["any"]}},
                    ],
                    "additionalProperties": False,
                },
                "condition": {
                    "type": "object",
                    "minProperties": 1,
                    "properties": {
                        "format_kind": {"$ref": "#/$defs/stringOrStringList"},
                        "indicator_type": {"$ref": "#/$defs/stringOrStringList"},
                        "regex": {"type": "string", "minLength": 1},
                        "contains": {"type": "string", "minLength": 1},
                        "hex": {"type": "string", "minLength": 1},
                        "high_entropy_chunks_at_least": {
                            "type": "integer",
                            "minimum": 1,
                        },
                        "pe_observation": {"$ref": "#/$defs/stringOrStringList"},
                        "container_entry_suffix": {
                            "$ref": "#/$defs/stringOrStringList",
                        },
                        "embedded_artifact": {"const": True},
                    },
                    "additionalProperties": False,
                },
                "stringOrStringList": {
                    "anyOf": [
                        {"type": "string", "minLength": 1},
                        {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string", "minLength": 1},
                        },
                    ]
                },
            },
        },
    ),
}


def schema_names() -> list[str]:
    """Return stable schema names accepted by the schema helpers."""
    return sorted(SCHEMAS)


def get_schema(name: str) -> dict[str, Any]:
    """Return a copy of one named schema."""
    key = _normalize_name(name)
    if key not in SCHEMAS:
        allowed = ", ".join(schema_names())
        raise ValueError(f"unknown schema {name!r}; expected one of: {allowed}")
    return copy.deepcopy(SCHEMAS[key])


def dumps_schema(name: str) -> str:
    """Return a named schema as formatted JSON."""
    return json.dumps(get_schema(name), indent=2) + "\n"


def export_schema(name: str, output: Path) -> Path:
    """Write one schema to a JSON file or to a directory."""
    key = _normalize_name(name)
    schema = get_schema(key)
    target = Path(output)
    if target.exists() and target.is_dir():
        target = target / f"{key}.schema.json"
    elif target.suffix == "":
        target.mkdir(parents=True, exist_ok=True)
        target = target / f"{key}.schema.json"
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    return target


def export_all_schemas(output_dir: Path) -> list[Path]:
    """Write every built-in schema to an output directory."""
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    return [export_schema(name, target / f"{name}.schema.json") for name in schema_names()]


def _normalize_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")
