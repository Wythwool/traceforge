"""Validation and export helpers for local rule sets."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from traceforge.rules import DEFAULT_RULES

ALLOWED_LEVELS = {"info", "low", "medium", "high", "critical"}
GROUP_KEYS = ("any", "all")
KNOWN_CONDITION_KEYS = {
    "format_kind",
    "indicator_type",
    "regex",
    "contains",
    "hex",
    "high_entropy_chunks_at_least",
    "pe_observation",
    "container_entry_suffix",
    "embedded_artifact",
}


def validate_ruleset(path: Path | None = None) -> dict:
    """Validate a JSON rule file, or the built-in rules when path is omitted."""
    payload, source = _read_document(path)
    rules = _extract_rules(payload)
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    summaries: list[dict[str, Any]] = []

    if not isinstance(rules, list):
        errors.append(
            {
                "rule": "document",
                "message": "expected a JSON list or an object with a rules list",
            }
        )
    else:
        seen_ids: set[str] = set()
        for index, rule in enumerate(rules):
            summaries.append(_summarize_rule(rule, index))
            _validate_rule(rule, index, seen_ids, errors, warnings)

    return {
        "source": source,
        "valid": not errors,
        "rule_count": len(rules) if isinstance(rules, list) else 0,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "errors": errors,
        "warnings": warnings,
        "rules": summaries,
    }


def describe_ruleset(path: Path | None = None) -> dict:
    """Return validation data with compact per-rule metadata."""
    return validate_ruleset(path)


def export_ruleset(output: Path, source: Path | None = None) -> Path:
    """Write a rule file using either built-in rules or another JSON source."""
    payload, _ = _read_document(source)
    rules = _extract_rules(payload)
    if not isinstance(rules, list):
        raise ValueError("rule source must be a JSON list or an object with a rules list")
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps({"rules": rules}, indent=2) + "\n",
        encoding="utf-8",
    )
    return destination


def _read_document(path: Path | None) -> tuple[Any, str]:
    if path is None:
        return {"rules": DEFAULT_RULES}, "built-in"
    source = Path(path)
    return json.loads(source.read_text(encoding="utf-8")), str(source)


def _extract_rules(payload: Any) -> Any:
    if isinstance(payload, dict):
        return payload.get("rules")
    return payload


def _validate_rule(
    rule: Any,
    index: int,
    seen_ids: set[str],
    errors: list[dict[str, str]],
    warnings: list[dict[str, str]],
) -> None:
    ref = _rule_ref(rule, index)
    if not isinstance(rule, dict):
        _add_error(errors, ref, "rule must be an object")
        return

    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        _add_error(errors, ref, "id must be a non-empty string")
    elif rule_id in seen_ids:
        _add_error(errors, rule_id, "id must be unique")
    else:
        seen_ids.add(rule_id)

    name = rule.get("name")
    if name is not None and (not isinstance(name, str) or not name.strip()):
        _add_error(errors, ref, "name must be a non-empty string when present")

    level = rule.get("level", "info")
    if not isinstance(level, str) or level not in ALLOWED_LEVELS:
        _add_error(
            errors,
            ref,
            "level must be one of: " + ", ".join(sorted(ALLOWED_LEVELS)),
        )

    description = rule.get("description")
    if not isinstance(description, str) or not description.strip():
        _add_warning(warnings, ref, "description is recommended")

    groups = [key for key in GROUP_KEYS if key in rule]
    if len(groups) != 1:
        _add_error(errors, ref, "provide exactly one of any or all")
        return

    group_name = groups[0]
    conditions = rule[group_name]
    if not isinstance(conditions, list) or not conditions:
        _add_error(errors, ref, f"{group_name} must be a non-empty list")
        return

    for condition_index, condition in enumerate(conditions):
        _validate_condition(
            condition,
            f"{ref}.{group_name}[{condition_index}]",
            errors,
        )


def _validate_condition(
    condition: Any,
    ref: str,
    errors: list[dict[str, str]],
) -> None:
    if not isinstance(condition, dict) or not condition:
        _add_error(errors, ref, "condition must be a non-empty object")
        return

    unknown = sorted(set(condition) - KNOWN_CONDITION_KEYS)
    for key in unknown:
        _add_error(errors, ref, f"unknown condition key: {key}")

    for key, value in condition.items():
        if key in {"format_kind", "indicator_type", "pe_observation"}:
            _validate_text_or_list(value, ref, key, errors)
        elif key == "container_entry_suffix":
            _validate_suffixes(value, ref, errors)
        elif key == "regex":
            _validate_regex(value, ref, errors)
        elif key == "contains":
            _validate_non_empty_text(value, ref, key, errors)
        elif key == "hex":
            _validate_hex(value, ref, errors)
        elif key == "high_entropy_chunks_at_least":
            _validate_positive_integer(value, ref, key, errors)
        elif key == "embedded_artifact":
            _validate_embedded_artifact(value, ref, errors)


def _validate_text_or_list(
    value: Any,
    ref: str,
    key: str,
    errors: list[dict[str, str]],
) -> None:
    if isinstance(value, str):
        if value.strip():
            return
        _add_error(errors, ref, f"{key} must not be empty")
        return
    if isinstance(value, list) and value:
        for item in value:
            if not isinstance(item, str) or not item.strip():
                _add_error(errors, ref, f"{key} list items must be non-empty strings")
                return
        return
    _add_error(errors, ref, f"{key} must be a string or a non-empty string list")


def _validate_suffixes(value: Any, ref: str, errors: list[dict[str, str]]) -> None:
    before = len(errors)
    _validate_text_or_list(value, ref, "container_entry_suffix", errors)
    if len(errors) != before:
        return
    suffixes = value if isinstance(value, list) else [value]
    for suffix in suffixes:
        if not str(suffix).startswith("."):
            _add_error(errors, ref, "container_entry_suffix values should start with .")
            return


def _validate_regex(value: Any, ref: str, errors: list[dict[str, str]]) -> None:
    if not isinstance(value, str) or not value:
        _add_error(errors, ref, "regex must be a non-empty string")
        return
    try:
        re.compile(value)
    except re.error as exc:
        _add_error(errors, ref, f"regex does not compile: {exc}")


def _validate_non_empty_text(
    value: Any,
    ref: str,
    key: str,
    errors: list[dict[str, str]],
) -> None:
    if not isinstance(value, str) or not value:
        _add_error(errors, ref, f"{key} must be a non-empty string")


def _validate_hex(value: Any, ref: str, errors: list[dict[str, str]]) -> None:
    if not isinstance(value, str) or not value.strip():
        _add_error(errors, ref, "hex must be a non-empty string")
        return
    compact = value.replace(" ", "")
    try:
        decoded = bytes.fromhex(compact)
    except ValueError as exc:
        _add_error(errors, ref, f"hex does not decode: {exc}")
        return
    if not decoded:
        _add_error(errors, ref, "hex must decode to at least one byte")


def _validate_positive_integer(
    value: Any,
    ref: str,
    key: str,
    errors: list[dict[str, str]],
) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _add_error(errors, ref, f"{key} must be an integer greater than zero")


def _validate_embedded_artifact(
    value: Any,
    ref: str,
    errors: list[dict[str, str]],
) -> None:
    if value is not True:
        _add_error(errors, ref, "embedded_artifact must be true")


def _summarize_rule(rule: Any, index: int) -> dict[str, Any]:
    if not isinstance(rule, dict):
        return {
            "id": f"rule[{index}]",
            "name": "",
            "level": "",
            "condition_count": 0,
            "description": "",
        }
    return {
        "id": rule.get("id", f"rule[{index}]"),
        "name": rule.get("name", ""),
        "level": rule.get("level", "info"),
        "condition_count": _condition_count(rule),
        "description": rule.get("description", ""),
    }


def _condition_count(rule: dict) -> int:
    total = 0
    for key in GROUP_KEYS:
        conditions = rule.get(key)
        if isinstance(conditions, list):
            total += len(conditions)
    return total


def _rule_ref(rule: Any, index: int) -> str:
    if isinstance(rule, dict) and isinstance(rule.get("id"), str) and rule["id"]:
        return rule["id"]
    return f"rule[{index}]"


def _add_error(errors: list[dict[str, str]], rule: str, message: str) -> None:
    errors.append({"rule": rule, "message": message})


def _add_warning(warnings: list[dict[str, str]], rule: str, message: str) -> None:
    warnings.append({"rule": rule, "message": message})
