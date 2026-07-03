"""Static capability grouping for extracted file facts."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

MAX_EVIDENCE_PER_CATEGORY = 20

CAPABILITY_DEFINITIONS: list[dict[str, Any]] = [
    {
        "id": "network",
        "name": "Network",
        "description": "Network-looking indicators or API names are present.",
        "indicator_types": {"url", "domain", "ipv4"},
        "patterns": [
            r"\b(socket|connect|send|recv|getaddrinfo|internet(open|connect|readfile))\b",
            r"\b(winhttp|wininet|url(download|open)|http(send|open)|wsastartup)\b",
            r"\b(curl|wget|libssl|libcurl)\b",
        ],
    },
    {
        "id": "filesystem",
        "name": "Filesystem",
        "description": "File path indicators or file I/O API names are present.",
        "indicator_types": {"path"},
        "patterns": [
            r"\b(createfile|readfile|writefile|deletefile|findfirstfile|copyfile)\b",
            r"\b(fopen|fread|fwrite|unlink|rename|opendir|readdir)\b",
        ],
    },
    {
        "id": "registry",
        "name": "Registry",
        "description": "Registry-style indicators or registry API names are present.",
        "indicator_types": {"registry_path"},
        "patterns": [r"\b(reg(open|create|set|query|delete)|hkey_)\b"],
    },
    {
        "id": "process",
        "name": "Process",
        "description": "Process creation or process-control names are present.",
        "patterns": [
            r"\b(createprocess[aw]?|shellexecute[aw]?|winexec)\b",
            r"\b(terminateprocess|openprocess)\b",
            r"\b(fork|execve|posix_spawn|system|popen)\b",
        ],
    },
    {
        "id": "memory-code",
        "name": "Memory and Code Loading",
        "description": "Dynamic loading or executable-memory API names are present.",
        "patterns": [
            r"\b(loadlibrary|getprocaddress|virtualalloc|virtualprotect|mapviewoffile)\b",
            r"\b(dlopen|dlsym|mmap|mprotect)\b",
        ],
    },
    {
        "id": "crypto",
        "name": "Cryptography",
        "description": "Cryptographic API names or algorithm strings are present.",
        "patterns": [
            r"\b(crypt(acquire|encrypt|decrypt|hash)|bcrypt|ncrypt|openssl)\b",
            r"\b(aes|rsa|sha-?1|sha-?256|sha-?512|md5|hmac|chacha|poly1305)\b",
        ],
    },
    {
        "id": "compression",
        "name": "Compression and Containers",
        "description": "Archive, compression, or packing-related names are present.",
        "format_kinds": {"zip", "apk", "jar"},
        "patterns": [
            r"\b(deflate|inflate|zlib|gzip|bzip2|lzma|xz|zip|rar|7z|upx)\b",
            r"\b(compress|uncompress)\b",
        ],
    },
    {
        "id": "scripting",
        "name": "Scripting",
        "description": "Command shell or script host names are present.",
        "patterns": [
            r"\b(powershell|cmd\.exe|wscript|cscript|mshta|rundll32)\b",
            r"\b(/bin/sh|/bin/bash|python|perl|ruby|node\.exe)\b",
        ],
    },
    {
        "id": "debug-diagnostics",
        "name": "Debug and Diagnostics",
        "description": "Debugging, tracing, or diagnostic names are present.",
        "patterns": [
            r"\b(isdebuggerpresent|checkremotedebuggerpresent|outputdebugstring)\b",
            r"\b(ptrace|debugbreak|pdb|symfromname)\b",
        ],
    },
    {
        "id": "system-info",
        "name": "System Information",
        "description": "System, user, host, or environment query names are present.",
        "patterns": [
            r"\b(getcomputername[aw]?|getusername[aw]?|gethostname|getenv|environment)\b",
            r"\b(uname|sysctl|getuid|getgid|whoami)\b",
        ],
    },
    {
        "id": "service-control",
        "name": "Service Control",
        "description": "Service manager API names are present.",
        "patterns": [
            r"\b(openscmanager|createservice|openservice|startservice|controlservice)\b",
            r"\b(deleteservice|changeserviceconfig)\b",
        ],
    },
]


def analyze_capabilities(extraction: dict[str, Any]) -> dict[str, Any]:
    """Group extracted facts into static capability categories."""
    candidates = _candidate_values(extraction)
    categories = []
    for definition in CAPABILITY_DEFINITIONS:
        category = _match_category(definition, extraction, candidates)
        if category is not None:
            categories.append(category)
    categories.sort(key=lambda item: (-item["evidence_count"], item["id"]))
    return {
        "engine": "traceforge-capabilities",
        "format": extraction.get("format", {}).get("kind", "raw"),
        "category_count": len(categories),
        "match_count": sum(item["evidence_count"] for item in categories),
        "summary": [item["id"] for item in categories],
        "categories": categories,
    }


def write_capabilities_csv(path: Path, payload: dict[str, Any]) -> Path:
    """Write capability evidence to CSV."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "category_id",
                "name",
                "confidence",
                "evidence_count",
                "source",
                "kind",
                "value",
                "reason",
            ]
        )
        for category in payload.get("categories", []):
            for item in category.get("evidence", []):
                writer.writerow(
                    [
                        category.get("id", ""),
                        category.get("name", ""),
                        category.get("confidence", ""),
                        category.get("evidence_count", ""),
                        item.get("source", ""),
                        item.get("kind", ""),
                        item.get("value", ""),
                        item.get("reason", ""),
                    ]
                )
    return destination


def dumps(payload: dict[str, Any]) -> str:
    """Return capability results as formatted JSON."""
    return json.dumps(payload, indent=2) + "\n"


def _match_category(
    definition: dict[str, Any],
    extraction: dict[str, Any],
    candidates: list[dict[str, str]],
) -> dict[str, Any] | None:
    evidence: list[dict[str, str]] = []
    evidence_count = 0

    if extraction.get("format", {}).get("kind") in definition.get("format_kinds", set()):
        evidence_count += 1
        evidence.append(
            {
                "source": "format",
                "kind": "format",
                "value": extraction.get("format", {}).get("kind", "raw"),
                "reason": "format kind",
            }
        )

    indicator_types = definition.get("indicator_types", set())
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in definition.get("patterns", [])]
    seen: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        matched_reason = _candidate_reason(candidate, indicator_types, compiled)
        if matched_reason is None:
            continue
        key = (candidate["source"], candidate["kind"], candidate["value"].lower())
        if key in seen:
            continue
        seen.add(key)
        evidence_count += 1
        if len(evidence) < MAX_EVIDENCE_PER_CATEGORY:
            evidence.append({**candidate, "reason": matched_reason})

    if evidence_count == 0:
        return None
    return {
        "id": definition["id"],
        "name": definition["name"],
        "description": definition["description"],
        "confidence": _confidence(evidence_count),
        "evidence_count": evidence_count,
        "evidence": evidence,
    }


def _candidate_reason(
    candidate: dict[str, str],
    indicator_types: set[str],
    patterns: list[re.Pattern[str]],
) -> str | None:
    if candidate["source"] == "indicator" and candidate["kind"] in indicator_types:
        return f"indicator type {candidate['kind']}"
    value = candidate["value"]
    for pattern in patterns:
        if pattern.search(value):
            return f"matched {pattern.pattern}"
    return None


def _candidate_values(extraction: dict[str, Any]) -> list[dict[str, str]]:
    values: list[dict[str, str]] = []
    for item in extraction.get("indicators", []):
        _add(values, "indicator", str(item.get("type", "")), item.get("value", ""))
    for source in ("ascii", "utf16le"):
        for value in extraction.get("strings", {}).get(source, {}).get("values", []):
            _add(values, f"string_{source}", "string", value)
    for value in _format_import_values(extraction):
        _add(values, "import", "symbol", value)
    for source in ("imports", "exports", "symbols"):
        for item in extraction.get("symbols", {}).get(source, []):
            _add(values, f"symbol_{source}", "symbol", item.get("name", ""))
    for item in extraction.get("signatures", {}).get("matches", []):
        _add(values, "signature", "signature", item.get("id", ""))
        _add(values, "signature", "signature", item.get("name", ""))
    for item in extraction.get("format", {}).get("embedded", []):
        _add(values, "format", "embedded", item.get("kind", ""))
    return values


def _format_import_values(extraction: dict[str, Any]) -> list[str]:
    details = extraction.get("format", {}).get("details", {})
    values: list[str] = []
    for item in details.get("imports", []):
        if isinstance(item, str):
            values.append(item)
        elif isinstance(item, dict) and "library" in item:
            library = str(item.get("library", ""))
            values.append(library)
            for symbol in item.get("symbols", []):
                name = str(symbol.get("name", ""))
                values.append(f"{library}!{name}" if library else name)
        elif isinstance(item, dict):
            module = str(item.get("module", ""))
            name = str(item.get("name", ""))
            values.extend([module, name, f"{module}!{name}" if module and name else ""])
    return [value for value in values if value]


def _add(values: list[dict[str, str]], source: str, kind: str, value: object) -> None:
    text = str(value).strip()
    if text:
        values.append({"source": source, "kind": kind, "value": text})


def _confidence(evidence_count: int) -> str:
    if evidence_count >= 5:
        return "high"
    if evidence_count >= 2:
        return "medium"
    return "low"
