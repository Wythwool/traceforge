"""Payload extraction helpers for parsed local files."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from traceforge.formats import analyze_format


def extract_payloads(
    path: Path,
    output_dir: Path,
    *,
    sections: bool = True,
    resources: bool = True,
    overlay: bool = True,
) -> dict:
    """Write selected byte ranges from a local file into an output directory."""
    source = Path(path)
    data = source.read_bytes()
    format_info = analyze_format(data, source.name)
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    if sections:
        records.extend(_extract_sections(data, format_info, target))
    if resources:
        records.extend(_extract_resources(data, format_info, target))
    if overlay:
        record = _extract_overlay(data, format_info, target)
        if record is not None:
            records.append(record)

    manifest = {
        "source_path": str(source.resolve()),
        "file_name": source.name,
        "format": format_info.get("kind", "raw"),
        "output_dir": str(target),
        "count": len(records),
        "records": records,
    }
    _write_json(target / "extract_manifest.json", manifest)
    _write_csv(target / "extracted_payloads.csv", records)
    return manifest


def _extract_sections(data: bytes, format_info: dict, output_dir: Path) -> list[dict]:
    details = format_info.get("details", {})
    items = details.get("sections", []) or details.get("segments", [])
    records = []
    for index, item in enumerate(items):
        offset = _first_int(item, "raw_offset", "offset", "fileoff")
        size = _first_int(item, "raw_size", "size", "filesize")
        label = item.get("name") or item.get("segment") or f"section_{index}"
        record = _write_range(
            data,
            output_dir,
            kind="section",
            index=index,
            label=str(label),
            offset=offset,
            size=size,
            suffix=".bin",
            metadata={
                "permissions": item.get("permissions", ""),
                "virtual_address": item.get("virtual_address", item.get("address")),
                "virtual_size": item.get("virtual_size", item.get("size")),
            },
        )
        if record is not None:
            records.append(record)
    return records


def _extract_resources(data: bytes, format_info: dict, output_dir: Path) -> list[dict]:
    resources = format_info.get("details", {}).get("resources", [])
    records = []
    for index, item in enumerate(resources):
        label = "_".join(
            part
            for part in (
                str(item.get("type", "")),
                str(item.get("name", "")),
                str(item.get("language", "")),
            )
            if part
        ) or f"resource_{index}"
        record = _write_range(
            data,
            output_dir,
            kind="resource",
            index=index,
            label=label,
            offset=item.get("offset"),
            size=item.get("size"),
            suffix=_resource_suffix(item),
            metadata={
                "type": item.get("type", ""),
                "type_id": item.get("type_id"),
                "name": item.get("name", ""),
                "language": item.get("language", ""),
                "rva": item.get("rva"),
                "codepage": item.get("codepage"),
            },
        )
        if record is not None:
            records.append(record)
    return records


def _extract_overlay(data: bytes, format_info: dict, output_dir: Path) -> dict | None:
    overlay = format_info.get("details", {}).get("overlay", {})
    if not overlay.get("present"):
        return None
    return _write_range(
        data,
        output_dir,
        kind="overlay",
        index=0,
        label="overlay",
        offset=overlay.get("offset"),
        size=overlay.get("size"),
        suffix=".bin",
        metadata={"entropy": overlay.get("entropy"), "reported_sha256": overlay.get("sha256")},
    )


def _write_range(
    data: bytes,
    output_dir: Path,
    *,
    kind: str,
    index: int,
    label: str,
    offset: Any,
    size: Any,
    suffix: str,
    metadata: dict[str, Any],
) -> dict | None:
    if not isinstance(offset, int) or not isinstance(size, int):
        return None
    if offset < 0 or size <= 0 or offset >= len(data):
        return None
    end = min(offset + size, len(data))
    blob = data[offset:end]
    if not blob:
        return None

    file_name = _file_name(kind, index, label, offset, suffix)
    path = output_dir / file_name
    path.write_bytes(blob)
    return {
        "kind": kind,
        "index": index,
        "label": label,
        "offset": offset,
        "size": len(blob),
        "requested_size": size,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "path": file_name,
        "metadata": {key: value for key, value in metadata.items() if value not in (None, "")},
    }


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _write_csv(path: Path, records: list[dict]) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["kind", "index", "label", "offset", "size", "sha256", "path", "metadata"]
        )
        for item in records:
            writer.writerow(
                [
                    item.get("kind", ""),
                    item.get("index", ""),
                    item.get("label", ""),
                    item.get("offset", ""),
                    item.get("size", ""),
                    item.get("sha256", ""),
                    item.get("path", ""),
                    json.dumps(item.get("metadata", {}), sort_keys=True),
                ]
            )
    return path


def _first_int(item: dict, *keys: str) -> int | None:
    for key in keys:
        value = item.get(key)
        if isinstance(value, int):
            return value
    return None


def _resource_suffix(item: dict) -> str:
    resource_type = str(item.get("type", "")).lower()
    if resource_type == "manifest":
        return ".xml"
    if resource_type in {"icon", "group_icon"}:
        return ".ico.bin"
    if resource_type == "bitmap":
        return ".bmp.bin"
    return ".bin"


def _file_name(kind: str, index: int, label: str, offset: int, suffix: str) -> str:
    clean = _slug(label) or kind
    clean_suffix = suffix if suffix.startswith(".") else f".{suffix}"
    return f"{kind}_{index:03d}_{clean}_{offset:08x}{clean_suffix}"


def _slug(value: str) -> str:
    lowered = value.strip().lower()
    lowered = re.sub(r"[^a-z0-9._-]+", "_", lowered)
    lowered = lowered.strip("._-")
    return lowered[:80]
