"""Analyst notes, tags, and status for stored cases."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

ANNOTATIONS_NAME = "annotations.json"
ANNOTATIONS_MARKDOWN_NAME = "annotations.md"
VALID_STATUSES = (
    "new",
    "triage",
    "in_progress",
    "interesting",
    "benign",
    "suspicious",
    "done",
)

_TAG_BREAK_RE = re.compile(r"[^\w.-]+", re.UNICODE)


def ensure_annotations(case_dir: Path, report: dict | None = None) -> list[Path]:
    """Create annotation files for a case when they do not exist yet."""
    target = Path(case_dir)
    json_path = target / ANNOTATIONS_NAME
    md_path = target / ANNOTATIONS_MARKDOWN_NAME
    if json_path.is_file() and md_path.is_file():
        return []
    payload = (
        load_annotations(target)
        if json_path.is_file()
        else default_annotations(target, report)
    )
    return write_annotations(target, payload)


def default_annotations(case_dir: Path, report: dict | None = None) -> dict:
    """Return a new annotation document for a case."""
    manifest = (report or {}).get("manifest", {})
    now = _utc_now()
    return {
        "schema": 1,
        "case_id": manifest.get("case_id", Path(case_dir).name),
        "file_name": manifest.get("file_name", ""),
        "created_utc": now,
        "updated_utc": now,
        "status": "new",
        "tags": [],
        "notes": [],
        "history": [
            {
                "time_utc": now,
                "action": "created",
                "value": "annotation log initialized",
            }
        ],
    }


def load_annotations(case_dir: Path) -> dict:
    """Load case annotations, or return a default document if none exists."""
    target = Path(case_dir)
    path = target / ANNOTATIONS_NAME
    if not path.is_file():
        return default_annotations(target)
    payload = json.loads(path.read_text(encoding="utf-8"))
    return _normalize_payload(target, payload)


def write_annotations(case_dir: Path, payload: dict) -> list[Path]:
    """Write annotations.json and annotations.md for a case."""
    target = Path(case_dir)
    target.mkdir(parents=True, exist_ok=True)
    normalized = _normalize_payload(target, payload)
    json_path = target / ANNOTATIONS_NAME
    md_path = target / ANNOTATIONS_MARKDOWN_NAME
    json_path.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_annotations_markdown(normalized), encoding="utf-8")
    return [json_path, md_path]


def update_annotations(
    case_dir: Path,
    *,
    status: str | None = None,
    add_tags: list[str] | tuple[str, ...] = (),
    remove_tags: list[str] | tuple[str, ...] = (),
    note_text: str | None = None,
    title: str | None = None,
    author: str | None = None,
) -> tuple[dict, list[Path]]:
    """Apply a case annotation update and write the annotation files."""
    target = Path(case_dir)
    payload = load_annotations(target)
    changes = []

    if status is not None:
        status = status.strip()
        if status not in VALID_STATUSES:
            allowed = ", ".join(VALID_STATUSES)
            raise ValueError(f"status must be one of: {allowed}")
        if payload.get("status") != status:
            payload["status"] = status
            changes.append(("status", status))

    existing_tags = set(payload.get("tags", []))
    added_tags = {normalize_tag(tag) for tag in add_tags}
    removed_tags = {normalize_tag(tag) for tag in remove_tags}
    next_tags = (existing_tags | added_tags) - removed_tags
    if sorted(next_tags) != payload.get("tags", []):
        payload["tags"] = sorted(next_tags)
        if added_tags:
            changes.append(("tag_added", ", ".join(sorted(added_tags))))
        if removed_tags:
            changes.append(("tag_removed", ", ".join(sorted(removed_tags))))

    if note_text is not None:
        text = note_text.strip()
        if not text:
            raise ValueError("note text cannot be empty")
        note_tags = sorted(added_tags)
        note = _new_note(text, title=title, author=author, tags=note_tags)
        payload.setdefault("notes", []).append(note)
        changes.append(("note_added", note["id"]))

    if not changes:
        return _normalize_payload(target, payload), []

    now = _utc_now()
    payload["updated_utc"] = now
    history = payload.setdefault("history", [])
    for action, value in changes:
        history.append({"time_utc": now, "action": action, "value": value})
    paths = write_annotations(target, payload)
    return load_annotations(target), paths


def render_annotations_markdown(payload: dict) -> str:
    """Render a compact Markdown view of case annotations."""
    tags = payload.get("tags", [])
    tag_text = ", ".join(f"`{_tick(tag)}`" for tag in tags) if tags else "none"
    lines = [
        f"# Case annotations: {payload.get('case_id', 'case')}",
        "",
        f"- File: `{_tick(payload.get('file_name', ''))}`",
        f"- Status: `{_tick(payload.get('status', 'new'))}`",
        f"- Tags: {tag_text}",
        f"- Updated: `{_tick(payload.get('updated_utc', ''))}`",
        "",
        "## Notes",
        "",
    ]
    notes = payload.get("notes", [])
    if not notes:
        lines.append("No notes recorded.")
    for note in notes:
        note_tags = note.get("tags", [])
        note_tag_text = (
            ", ".join(f"`{_tick(tag)}`" for tag in note_tags) if note_tags else "none"
        )
        lines.extend(
            [
                f"### {_plain(note.get('title') or note.get('id', 'note'))}",
                "",
                f"- ID: `{_tick(note.get('id', ''))}`",
                f"- Created: `{_tick(note.get('created_utc', ''))}`",
                f"- Author: `{_tick(note.get('author', 'analyst'))}`",
                f"- Tags: {note_tag_text}",
                "",
                _plain(note.get("text", "")),
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def normalize_tag(value: str) -> str:
    """Normalize a user supplied tag without losing readable words."""
    tag = _TAG_BREAK_RE.sub("-", value.strip().lower()).strip("-._")
    if not tag:
        raise ValueError("tag cannot be empty")
    return tag[:64]


def _normalize_payload(case_dir: Path, payload: dict) -> dict:
    status = payload.get("status") or "new"
    if status not in VALID_STATUSES:
        status = "new"
    tags = sorted({normalize_tag(str(tag)) for tag in payload.get("tags", []) if str(tag)})
    notes = [_normalize_note(note) for note in payload.get("notes", [])]
    history = [
        {
            "time_utc": str(item.get("time_utc", "")),
            "action": str(item.get("action", "")),
            "value": str(item.get("value", "")),
        }
        for item in payload.get("history", [])
        if isinstance(item, dict)
    ]
    created = payload.get("created_utc") or _utc_now()
    updated = payload.get("updated_utc") or created
    return {
        "schema": 1,
        "case_id": str(payload.get("case_id") or Path(case_dir).name),
        "file_name": str(payload.get("file_name", "")),
        "created_utc": str(created),
        "updated_utc": str(updated),
        "status": status,
        "tags": tags,
        "notes": notes,
        "history": history,
    }


def _new_note(
    text: str,
    *,
    title: str | None = None,
    author: str | None = None,
    tags: list[str],
) -> dict:
    now = _utc_now()
    note_title = (title or "").strip()
    digest = hashlib.sha1(f"{now}\0{note_title}\0{text}".encode()).hexdigest()
    return {
        "id": f"note-{now.replace('-', '').replace(':', '')[:15]}-{digest[:8]}",
        "created_utc": now,
        "author": (author or "analyst").strip() or "analyst",
        "title": note_title,
        "text": text,
        "tags": tags,
    }


def _normalize_note(note: dict) -> dict:
    if not isinstance(note, dict):
        note = {}
    text = str(note.get("text", ""))
    created = str(note.get("created_utc") or _utc_now())
    note_id = str(note.get("id") or _note_id(created, text))
    return {
        "id": note_id,
        "created_utc": created,
        "author": str(note.get("author") or "analyst"),
        "title": str(note.get("title") or ""),
        "text": text,
        "tags": sorted(
            {normalize_tag(str(tag)) for tag in note.get("tags", []) if str(tag)}
        ),
    }


def _note_id(created: str, text: str) -> str:
    digest = hashlib.sha1(f"{created}\0{text}".encode()).hexdigest()
    return f"note-{digest[:12]}"


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tick(value: object) -> str:
    return str(value).replace("`", "'")


def _plain(value: object) -> str:
    return str(value).replace("\r\n", "\n").replace("\r", "\n").strip()
