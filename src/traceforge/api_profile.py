"""Import and API-family profiling for parsed executable metadata."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

MAX_IMPORT_ROWS = 2048
MAX_LIBRARY_ROWS = 256
MAX_FAMILY_ROWS = 64
MAX_EVIDENCE_PER_FAMILY = 64
MAX_SYMBOLS_PER_LIBRARY = 128

API_FAMILIES: tuple[dict[str, Any], ...] = (
    {
        "id": "network",
        "name": "Network",
        "description": "Network sockets, HTTP, URL, and address-resolution APIs.",
        "patterns": (
            r"\bsocket\b", r"\bconnect\b", r"\bbind\b", r"\blisten\b", r"\baccept\b",
            r"\bsend\b", r"\brecv\b", r"\bgetaddrinfo\b", r"\binet_", r"winhttp",
            r"wininet", r"internet(open|connect|read|write)", r"http(open|send|query)",
            r"urldownload", r"curl_", r"ssl_", r"bio_",
        ),
    },
    {
        "id": "filesystem",
        "name": "Filesystem",
        "description": "File and directory access APIs.",
        "patterns": (
            r"createfile", r"readfile", r"writefile", r"deletefile", r"copyfile",
            r"movefile", r"findfirstfile", r"getfile", r"setfile", r"\bfopen\b",
            r"\bfread\b", r"\bfwrite\b", r"\bopen\b", r"\bread\b", r"\bwrite\b",
            r"\bunlink\b", r"\bstat\b", r"\bmkdir\b", r"\brmdir\b",
        ),
    },
    {
        "id": "registry",
        "name": "Registry",
        "description": "Windows registry key and value APIs.",
        "patterns": (
            r"\breg(open|create|set|query|delete|enum|close)", r"nt(open|create|set|query)key",
            r"zw(open|create|set|query)key",
        ),
    },
    {
        "id": "process-thread",
        "name": "Process and Thread",
        "description": "Process, thread, and command-launch APIs.",
        "patterns": (
            r"createprocess", r"shellexecute", r"\bwinexec\b", r"openprocess",
            r"terminateprocess", r"createthread", r"queueuserapc", r"createprocessasuser",
            r"\bfork\b", r"\bexecv", r"\bsystem\b", r"\bpopen\b", r"posix_spawn",
        ),
    },
    {
        "id": "memory",
        "name": "Memory and Loader",
        "description": "Memory mapping, protection, and dynamic loader APIs.",
        "patterns": (
            r"virtualalloc", r"virtualprotect", r"virtualfree", r"writeprocessmemory",
            r"readprocessmemory", r"mapviewoffile", r"loadlibrary", r"getprocaddress",
            r"\bmmap\b", r"\bmprotect\b", r"\bdlopen\b", r"\bdlsym\b",
        ),
    },
    {
        "id": "crypto",
        "name": "Cryptography",
        "description": "Cryptographic, certificate, and hashing APIs.",
        "patterns": (
            r"\bcrypt", r"\bbcrypt", r"\bncrypt", r"\bcert", r"openssl", r"\bevp_",
            r"\baes_", r"\brsa_", r"\bsha[0-9_]*\b", r"\bmd5\b", r"\bhmac",
        ),
    },
    {
        "id": "compression",
        "name": "Compression",
        "description": "Compression and archive helper APIs.",
        "patterns": (
            r"\binflate\b", r"\bdeflate\b", r"\bzlib\b", r"\blzma\b", r"\bbz2\b",
            r"\buncompress\b", r"\bcompress\b",
        ),
    },
    {
        "id": "service-control",
        "name": "Service Control",
        "description": "Windows service manager APIs.",
        "patterns": (
            r"openscmanager", r"createservice", r"openservice", r"startservice",
            r"controlservice", r"deleteservice", r"changeserviceconfig",
        ),
    },
    {
        "id": "debug-diagnostics",
        "name": "Debug and Diagnostics",
        "description": "Debug checks, tracing, and diagnostic APIs.",
        "patterns": (
            r"isdebuggerpresent", r"checkremotedebuggerpresent", r"outputdebugstring",
            r"\bdebugbreak\b", r"\bptrace\b", r"\bsysctl\b", r"raiseexception",
        ),
    },
    {
        "id": "system-info",
        "name": "System Information",
        "description": "Host, user, environment, and OS information APIs.",
        "patterns": (
            r"getcomputername", r"getusername", r"getversion", r"getsysteminfo",
            r"globalmemorystatus", r"\bgetenv\b", r"\buname\b", r"\bgetuid\b",
            r"\bgetgid\b", r"\bgethostname\b",
        ),
    },
    {
        "id": "synchronization",
        "name": "Synchronization",
        "description": "Mutex, event, lock, and wait APIs.",
        "patterns": (
            r"createmutex", r"openmutex", r"createevent", r"setevent", r"resetevent",
            r"waitforsingleobject", r"criticalsection", r"pthread_mutex",
        ),
    },
    {
        "id": "user-interface",
        "name": "User Interface",
        "description": "Window, dialog, and message APIs.",
        "patterns": (
            r"messagebox", r"createwindow", r"dialogbox", r"setwindow", r"getwindow",
            r"dispatchmessage", r"sendmessage", r"postmessage",
        ),
    },
)

LIBRARY_CATEGORIES = (
    ("network", ("ws2_32", "wininet", "winhttp", "urlmon", "libcurl", "libssl")),
    ("crypto", ("crypt32", "bcrypt", "ncrypt", "libcrypto", "openssl")),
    ("registry-service", ("advapi32",)),
    ("native-runtime", ("kernel32", "kernelbase", "ntdll", "libc", "libsystem")),
    ("ui", ("user32", "gdi32", "comctl32", "uxtheme")),
    ("shell-com", ("shell32", "ole32", "oleaut32", "shlwapi")),
    ("compression", ("zlib", "libz", "liblzma", "libbz2")),
)


def analyze_api_profile(extraction: dict[str, Any], filename: str = "") -> dict[str, Any]:
    """Build a normalized API and import-family profile."""
    imports = _collect_imports(extraction)
    libraries = _library_summary(imports, extraction)
    families = _family_summary(imports)
    return {
        "engine": "traceforge-api-profile",
        "file_name": filename,
        "format": extraction.get("format", {}).get("kind", "raw"),
        "import_count": len(imports),
        "library_count": len(libraries),
        "family_count": len(families),
        "families": families[:MAX_FAMILY_ROWS],
        "libraries": libraries[:MAX_LIBRARY_ROWS],
        "imports": imports[:MAX_IMPORT_ROWS],
        "truncated": {
            "imports": len(imports) > MAX_IMPORT_ROWS,
            "libraries": len(libraries) > MAX_LIBRARY_ROWS,
            "families": len(families) > MAX_FAMILY_ROWS,
        },
    }


def write_api_profile_csv(path: Path, payload: dict[str, Any]) -> Path:
    """Write API profile rows for spreadsheet review."""
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["row_type", "family_id", "library", "name", "kind", "ordinal", "source", "detail"]
        )
        for family in payload.get("families", []):
            for evidence in family.get("evidence", []):
                writer.writerow(
                    [
                        "family",
                        family.get("id", ""),
                        evidence.get("library", ""),
                        evidence.get("name", ""),
                        evidence.get("kind", ""),
                        evidence.get("ordinal", ""),
                        evidence.get("source", ""),
                        evidence.get("reason", ""),
                    ]
                )
        for library in payload.get("libraries", []):
            writer.writerow(
                [
                    "library",
                    "",
                    library.get("name", ""),
                    "",
                    "",
                    "",
                    library.get("category", ""),
                    f"imports={library.get('import_count', 0)}",
                ]
            )
        for item in payload.get("imports", []):
            writer.writerow(
                [
                    "import",
                    ";".join(item.get("families", [])),
                    item.get("library", ""),
                    item.get("name", ""),
                    item.get("kind", ""),
                    item.get("ordinal", ""),
                    item.get("source", ""),
                    "",
                ]
            )
    return Path(path)


def dumps(payload: dict[str, Any]) -> str:
    """Render stable JSON for CLI output."""
    return json.dumps(payload, indent=2) + "\n"


def _collect_imports(extraction: dict[str, Any]) -> list[dict[str, Any]]:
    details = extraction.get("format", {}).get("details", {})
    rows: list[dict[str, Any]] = []
    rows.extend(_imports_from_format(details))
    rows.extend(_imports_from_symbols(extraction.get("symbols", {})))
    return _dedupe_imports(rows)


def _imports_from_format(details: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in details.get("imports", []):
        if isinstance(item, str):
            rows.append(_import_row(item, "", "", "", "format"))
            continue
        if "library" in item:
            library = item.get("library", "")
            symbols = item.get("symbols", [])
            if not symbols and library:
                rows.append(_import_row(library, "", "", "", "format"))
            for symbol in symbols:
                name = symbol.get("name") or (
                    f"ordinal_{symbol.get('ordinal')}" if symbol.get("ordinal") else ""
                )
                row = _import_row(
                    library,
                    name,
                    symbol.get("kind", ""),
                    symbol.get("ordinal", ""),
                    "format",
                )
                row["iat_rva"] = symbol.get("iat_rva")
                row["iat_address"] = symbol.get("iat_address")
                rows.append(row)
        elif "module" in item:
            rows.append(
                _import_row(
                    item.get("module", ""),
                    item.get("name", ""),
                    str(item.get("kind", "")),
                    "",
                    "format",
                )
            )
        elif item.get("name"):
            rows.append(_import_row("", item.get("name", ""), item.get("kind", ""), "", "format"))
    return rows


def _imports_from_symbols(symbols: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in symbols.get("imports", []):
        rows.append(
            _import_row(
                item.get("library", ""),
                item.get("name", ""),
                item.get("kind", item.get("type", "")),
                item.get("ordinal", ""),
                "symbols",
            )
        )
    return rows


def _import_row(
    library: Any,
    name: Any,
    kind: Any,
    ordinal: Any,
    source: str,
) -> dict[str, Any]:
    library_text = str(library or "")
    name_text = str(name or "")
    families = _families_for_symbol(name_text)
    return {
        "library": library_text,
        "library_normalized": _normalize_library(library_text),
        "library_category": _library_category(library_text),
        "name": name_text,
        "name_normalized": _normalize_symbol(name_text),
        "kind": str(kind or ""),
        "ordinal": ordinal if ordinal is not None else "",
        "source": source,
        "families": families,
    }


def _library_summary(
    imports: list[dict[str, Any]],
    extraction: dict[str, Any],
) -> list[dict[str, Any]]:
    by_library: dict[str, dict[str, Any]] = {}
    for item in imports:
        name = item.get("library") or "(unbound)"
        key = item.get("library_normalized") or name.lower()
        library = by_library.setdefault(
            key,
            {
                "name": name,
                "normalized": key,
                "category": item.get("library_category", ""),
                "import_count": 0,
                "families": set(),
                "symbols": [],
            },
        )
        library["import_count"] += 1
        library["families"].update(item.get("families", []))
        if item.get("name") and len(library["symbols"]) < MAX_SYMBOLS_PER_LIBRARY:
            library["symbols"].append(item["name"])

    details = extraction.get("format", {}).get("details", {})
    for name in (
        details.get("linked_libraries", [])
        + details.get("needed_libraries", [])
        + extraction.get("symbols", {}).get("needed_libraries", [])
    ):
        key = _normalize_library(str(name))
        by_library.setdefault(
            key,
            {
                "name": str(name),
                "normalized": key,
                "category": _library_category(str(name)),
                "import_count": 0,
                "families": set(),
                "symbols": [],
            },
        )

    rows = []
    for item in by_library.values():
        rows.append(
            {
                "name": item["name"],
                "normalized": item["normalized"],
                "category": item["category"],
                "import_count": item["import_count"],
                "families": sorted(item["families"]),
                "symbols": item["symbols"],
            }
        )
    return sorted(rows, key=lambda row: (-row["import_count"], row["normalized"]))


def _family_summary(imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    families: dict[str, dict[str, Any]] = {}
    definitions = {item["id"]: item for item in API_FAMILIES}
    for item in imports:
        for family_id in item.get("families", []):
            definition = definitions[family_id]
            family = families.setdefault(
                family_id,
                {
                    "id": family_id,
                    "name": definition["name"],
                    "description": definition["description"],
                    "import_count": 0,
                    "libraries": set(),
                    "evidence": [],
                },
            )
            family["import_count"] += 1
            if item.get("library"):
                family["libraries"].add(item["library"])
            if len(family["evidence"]) < MAX_EVIDENCE_PER_FAMILY:
                family["evidence"].append(
                    {
                        "library": item.get("library", ""),
                        "name": item.get("name", ""),
                        "kind": item.get("kind", ""),
                        "ordinal": item.get("ordinal", ""),
                        "source": item.get("source", ""),
                        "reason": family_id,
                    }
                )

    rows = []
    for item in families.values():
        libraries = sorted(item["libraries"])
        rows.append(
            {
                "id": item["id"],
                "name": item["name"],
                "description": item["description"],
                "confidence": _confidence(item["import_count"], len(libraries)),
                "import_count": item["import_count"],
                "libraries": libraries,
                "evidence": item["evidence"],
            }
        )
    return sorted(rows, key=lambda row: (-row["import_count"], row["id"]))


def _families_for_symbol(name: str) -> list[str]:
    normalized = _normalize_symbol(name)
    if not normalized:
        return []
    families = []
    for family in API_FAMILIES:
        if any(re.search(pattern, normalized) for pattern in family["patterns"]):
            families.append(family["id"])
    return families


def _dedupe_imports(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = []
    seen = set()
    for item in rows:
        key = (
            item.get("library_normalized", ""),
            item.get("name_normalized", ""),
            str(item.get("ordinal", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _normalize_symbol(value: str) -> str:
    raw = value.strip()
    name = raw.lower()
    for prefix in ("__imp_", "_imp_", "_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    name = re.sub(r"@[0-9]+$", "", name)
    if len(raw) > 1 and raw[-1] in {"A", "W"}:
        name = name[:-1]
    return name


def _normalize_library(value: str) -> str:
    name = Path(value.replace("\\", "/")).name.lower()
    for suffix in (".dll", ".so", ".dylib", ".a"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    name = re.sub(r"\.so(?:\.[0-9]+)+$", "", name)
    return name


def _library_category(value: str) -> str:
    normalized = _normalize_library(value)
    if not normalized:
        return ""
    for category, needles in LIBRARY_CATEGORIES:
        if any(needle in normalized for needle in needles):
            return category
    return "library"


def _confidence(import_count: int, library_count: int) -> str:
    if import_count >= 6 or library_count >= 2:
        return "high"
    if import_count >= 2:
        return "medium"
    return "low"
