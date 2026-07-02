"""Portable case bundle creation, verification, and import."""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from tempfile import mkdtemp
from typing import Any

from traceforge import __version__

BUNDLE_KIND = "traceforge.case-bundle"
BUNDLE_SCHEMA_VERSION = 1
BUNDLE_MANIFEST_NAME = "bundle_manifest.json"
CASE_ARCHIVE_PREFIX = "case"


def create_case_bundle(case_dir: Path, output: Path | None = None) -> Path:
    """Write a portable zip bundle for one case directory."""
    source = Path(case_dir)
    if not (source / "report.json").is_file():
        raise FileNotFoundError(f"no report.json in {source}")

    manifest = build_bundle_manifest(source)
    destination = _bundle_destination(output, manifest["case_id"])
    if _is_inside(destination.resolve(strict=False), source.resolve()):
        raise ValueError("bundle output must not be inside the case directory")
    destination.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        archive.writestr(
            BUNDLE_MANIFEST_NAME,
            json.dumps(manifest, indent=2) + "\n",
        )
        for item in manifest["files"]:
            archive.write(
                source / Path(item["path"]),
                f"{CASE_ARCHIVE_PREFIX}/{item['path']}",
            )
    return destination


def build_bundle_manifest(case_dir: Path) -> dict[str, Any]:
    """Build the manifest that is stored inside a case bundle."""
    source = Path(case_dir)
    case_id = _case_id(source)
    files = _case_file_records(source)
    return {
        "kind": BUNDLE_KIND,
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "created_utc": _utc_now(),
        "tool": "traceforge",
        "tool_version": __version__,
        "case_id": case_id,
        "file_count": len(files),
        "total_size": sum(item["size"] for item in files),
        "files": files,
    }


def verify_case_bundle(bundle: Path) -> dict[str, Any]:
    """Verify bundle structure and per-file hashes."""
    source = Path(bundle)
    result: dict[str, Any] = {
        "bundle": str(source),
        "valid": False,
        "case_id": "",
        "file_count": 0,
        "verified_count": 0,
        "total_size": 0,
        "errors": [],
        "warnings": [],
        "manifest": {},
    }
    try:
        with zipfile.ZipFile(source) as archive:
            manifest = _read_bundle_manifest(archive)
            result["manifest"] = manifest
            result["case_id"] = str(manifest.get("case_id", ""))
            result["file_count"] = _safe_count(manifest.get("file_count"))
            result["total_size"] = _safe_count(manifest.get("total_size"))
            _verify_manifest_shape(manifest, result["errors"])
            _verify_archive_files(archive, manifest, result)
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, KeyError) as exc:
        result["errors"].append(str(exc))
    result["valid"] = not result["errors"]
    return result


def import_case_bundle(
    bundle: Path,
    cases_root: Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Verify and import a case bundle into a cases root."""
    verification = verify_case_bundle(bundle)
    if not verification["valid"]:
        detail = "; ".join(verification["errors"][:3])
        raise ValueError(f"bundle verification failed: {detail}")

    manifest = verification["manifest"]
    case_id = _clean_case_id(manifest.get("case_id", ""))
    root = Path(cases_root)
    root.mkdir(parents=True, exist_ok=True)
    target = root / case_id
    target_exists = target.exists()
    if target_exists and not overwrite:
        raise FileExistsError(f"case already exists: {target}")

    temp_dir = Path(mkdtemp(prefix=f".importing-{case_id}-", dir=root))
    try:
        with zipfile.ZipFile(bundle) as archive:
            for item in manifest["files"]:
                rel_path = _clean_manifest_path(item.get("path"))
                destination = _case_file_path(temp_dir, rel_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(
                    archive.read(f"{CASE_ARCHIVE_PREFIX}/{rel_path}")
                )
        if target_exists:
            _remove_existing_case(target, root)
        temp_dir.replace(target)
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise

    return {
        "bundle": str(Path(bundle)),
        "case_id": case_id,
        "case_dir": str(target),
        "file_count": verification["verified_count"],
        "overwritten": target_exists,
    }


def _case_file_records(case_dir: Path) -> list[dict[str, Any]]:
    records = []
    for path in sorted(entry for entry in case_dir.rglob("*") if entry.is_file()):
        rel_path = path.relative_to(case_dir).as_posix()
        clean = _clean_manifest_path(rel_path)
        data = path.read_bytes()
        records.append(
            {
                "path": clean,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return records


def _read_bundle_manifest(archive: zipfile.ZipFile) -> dict[str, Any]:
    return json.loads(archive.read(BUNDLE_MANIFEST_NAME).decode("utf-8"))


def _verify_manifest_shape(manifest: dict[str, Any], errors: list[str]) -> None:
    if manifest.get("kind") != BUNDLE_KIND:
        errors.append("manifest kind is not traceforge.case-bundle")
    if manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        errors.append("unsupported bundle schema version")
    try:
        _clean_case_id(manifest.get("case_id", ""))
    except ValueError as exc:
        errors.append(str(exc))
    files = manifest.get("files")
    if not isinstance(files, list):
        errors.append("manifest files must be a list")
        return
    if manifest.get("file_count") != len(files):
        errors.append("manifest file_count does not match files")


def _verify_archive_files(
    archive: zipfile.ZipFile,
    manifest: dict[str, Any],
    result: dict[str, Any],
) -> None:
    names = [item.filename for item in archive.infolist() if not item.is_dir()]
    name_set = set(names)
    if len(names) != len(name_set):
        result["errors"].append("bundle contains duplicate archive entries")

    expected = {BUNDLE_MANIFEST_NAME}
    total_size = 0
    for index, item in enumerate(manifest.get("files", [])):
        if not isinstance(item, dict):
            result["errors"].append(f"file entry {index} must be an object")
            continue
        try:
            rel_path = _clean_manifest_path(item.get("path"))
        except ValueError as exc:
            result["errors"].append(str(exc))
            continue
        archive_path = f"{CASE_ARCHIVE_PREFIX}/{rel_path}"
        expected.add(archive_path)
        if archive_path not in name_set:
            result["errors"].append(f"missing archive entry: {archive_path}")
            continue
        data = archive.read(archive_path)
        actual_size = len(data)
        actual_sha256 = hashlib.sha256(data).hexdigest()
        total_size += actual_size
        file_ok = True
        if item.get("size") != actual_size:
            result["errors"].append(f"size mismatch: {rel_path}")
            file_ok = False
        if item.get("sha256") != actual_sha256:
            result["errors"].append(f"sha256 mismatch: {rel_path}")
            file_ok = False
        if file_ok:
            result["verified_count"] += 1

    if manifest.get("total_size") != total_size:
        result["errors"].append("manifest total_size does not match files")

    extra = sorted(name_set - expected)
    if extra:
        preview = ", ".join(extra[:10])
        result["warnings"].append(f"bundle contains extra entries: {preview}")


def _case_id(case_dir: Path) -> str:
    manifest_path = case_dir / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        value = manifest.get("case_id")
        if isinstance(value, str) and value:
            return _clean_case_id(value)
    return _clean_case_id(case_dir.name)


def _clean_case_id(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("case_id must be a non-empty string")
    normalized = value.strip().replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or len(path.parts) != 1 or path.name in {"", ".", ".."}:
        raise ValueError("case_id must be a single path segment")
    return path.name


def _clean_manifest_path(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("manifest file path must be a non-empty string")
    normalized = value.strip().replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute():
        raise ValueError(f"manifest file path is absolute: {value}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"manifest file path is unsafe: {value}")
    return path.as_posix()


def _case_file_path(root: Path, rel_path: str) -> Path:
    target = root / Path(rel_path)
    if not _is_inside(target.resolve(strict=False), root.resolve()):
        raise ValueError(f"case file path escapes target directory: {rel_path}")
    return target


def _remove_existing_case(target: Path, cases_root: Path) -> None:
    root = cases_root.resolve()
    resolved = target.resolve(strict=False)
    if not _is_inside(resolved, root):
        raise ValueError(f"refusing to replace case outside cases root: {target}")
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()


def _bundle_destination(output: Path | None, case_id: str) -> Path:
    file_name = f"{case_id}.traceforge.zip"
    if output is None:
        return Path(file_name)
    target = Path(output)
    if target.exists() and target.is_dir():
        return target / file_name
    return target


def _safe_count(value: object) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
