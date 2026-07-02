"""Deterministic local rule evaluation for TraceForge reports."""

from __future__ import annotations

import json
import re
from pathlib import Path

DEFAULT_RULES = [
    {
        "id": "format.executable",
        "name": "Executable container",
        "level": "info",
        "any": [{"format_kind": ["pe", "elf", "macho", "wasm"]}],
        "description": "File format is an executable or loadable binary container.",
    },
    {
        "id": "format.archive_code",
        "name": "Archive with code-like entries",
        "level": "info",
        "any": [{"container_entry_suffix": [".class", ".dex", ".so", ".dll", ".exe"]}],
        "description": "Archive contains entries commonly used for code or native libraries.",
    },
    {
        "id": "pe.writable_executable_section",
        "name": "Writable executable PE section",
        "level": "medium",
        "any": [{"pe_observation": "pe_writable_executable_section"}],
        "description": "A PE section is both writable and executable.",
    },
    {
        "id": "entropy.high_regions",
        "name": "High entropy regions",
        "level": "medium",
        "any": [{"high_entropy_chunks_at_least": 3}],
        "description": "Multiple chunks have high byte entropy.",
    },
    {
        "id": "indicators.network",
        "name": "Network indicators",
        "level": "info",
        "any": [{"indicator_type": ["url", "domain", "ipv4"]}],
        "description": "Network-looking values were found in extracted strings.",
    },
    {
        "id": "indicators.registry",
        "name": "Registry-style paths",
        "level": "info",
        "any": [{"indicator_type": "registry_path"}],
        "description": "Registry-style paths were found in extracted strings.",
    },
    {
        "id": "artifact.embedded",
        "name": "Embedded binary artifact",
        "level": "medium",
        "any": [{"embedded_artifact": True}],
        "description": "Known binary magic appears inside the file away from offset zero.",
    },
]

HIGH_ENTROPY_THRESHOLD = 7.2


def load_rules(path: Path | None) -> list[dict]:
    """Load external JSON rules, or return built-ins when no path is provided."""
    if path is None:
        return DEFAULT_RULES
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        rules = payload.get("rules", [])
    else:
        rules = payload
    if not isinstance(rules, list):
        raise ValueError("rule file must contain a JSON list or {'rules': [...]}")
    return rules


def evaluate_rules(extraction: dict, rules: list[dict] | None = None) -> dict:
    """Evaluate simple local rules against an extraction result."""
    active_rules = DEFAULT_RULES if rules is None else rules
    matches = []
    for rule in active_rules:
        evidence = _match_rule(rule, extraction)
        if evidence:
            matches.append(
                {
                    "id": rule.get("id", "unnamed"),
                    "name": rule.get("name", rule.get("id", "unnamed")),
                    "level": rule.get("level", "info"),
                    "description": rule.get("description", ""),
                    "evidence": evidence[:10],
                }
            )
    return {
        "engine": "traceforge-local",
        "rule_count": len(active_rules),
        "match_count": len(matches),
        "matches": sorted(matches, key=lambda item: (item["level"], item["id"])),
    }


def _match_rule(rule: dict, extraction: dict) -> list[str]:
    groups = rule.get("all")
    if groups:
        evidence = []
        for condition in groups:
            condition_evidence = _match_condition(condition, extraction)
            if not condition_evidence:
                return []
            evidence.extend(condition_evidence)
        return evidence

    groups = rule.get("any", [])
    evidence = []
    for condition in groups:
        evidence.extend(_match_condition(condition, extraction))
    return evidence


def _match_condition(condition: dict, extraction: dict) -> list[str]:
    evidence = []
    if "format_kind" in condition:
        kinds = _as_set(condition["format_kind"])
        kind = extraction.get("format", {}).get("kind")
        if kind in kinds:
            evidence.append(f"format={kind}")

    if "indicator_type" in condition:
        kinds = _as_set(condition["indicator_type"])
        values = [
            item["value"]
            for item in extraction.get("indicators", [])
            if item.get("type") in kinds
        ]
        evidence.extend(f"indicator={value}" for value in values[:5])

    if "regex" in condition:
        pattern = re.compile(condition["regex"], re.IGNORECASE)
        for source in ("ascii", "utf16le"):
            for value in extraction.get("strings", {}).get(source, {}).get("values", []):
                if pattern.search(value):
                    evidence.append(f"{source}:{value[:120]}")
                    break

    if "contains" in condition:
        needle = str(condition["contains"]).lower()
        for source in ("ascii", "utf16le"):
            for value in extraction.get("strings", {}).get(source, {}).get("values", []):
                if needle in value.lower():
                    evidence.append(f"{source}:{value[:120]}")
                    break

    if "hex" in condition:
        needle = bytes.fromhex(str(condition["hex"]).replace(" ", ""))
        first_hex = extraction.get("first_bytes_hex", "")
        if needle and first_hex.startswith(needle.hex()):
            evidence.append(f"first_bytes={first_hex}")

    if "high_entropy_chunks_at_least" in condition:
        needed = int(condition["high_entropy_chunks_at_least"])
        chunks = [
            item
            for item in extraction.get("chunks", {}).get("records", [])
            if item.get("entropy", 0.0) >= HIGH_ENTROPY_THRESHOLD
        ]
        if len(chunks) >= needed:
            evidence.append(f"high_entropy_chunks={len(chunks)}")

    if "pe_observation" in condition:
        wanted = condition["pe_observation"]
        observations = (
            extraction.get("format", {})
            .get("details", {})
            .get("observations", [])
        )
        for observation in observations:
            if observation.get("id") == wanted:
                evidence.append(observation.get("detail", wanted))

    if "container_entry_suffix" in condition:
        suffixes = tuple(
            str(value).lower()
            for value in _as_set(condition["container_entry_suffix"])
        )
        entries = (
            extraction.get("format", {})
            .get("details", {})
            .get("entries", [])
        )
        for entry in entries:
            name = entry.get("name", "").lower()
            if name.endswith(suffixes):
                evidence.append(f"entry={entry.get('name')}")
                if len(evidence) >= 5:
                    break

    if condition.get("embedded_artifact"):
        artifacts = extraction.get("format", {}).get("embedded", [])
        evidence.extend(f"{item['kind']}@{item['offset']}" for item in artifacts[:5])

    return evidence


def _as_set(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list | tuple | set):
        return {str(item) for item in value}
    return {str(value)}
