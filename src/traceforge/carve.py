"""Embedded artifact carving for inert byte streams."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from traceforge.formats import find_embedded_artifacts

MAX_CARVE_BYTES = 64 * 1024 * 1024

EXTENSIONS = {
    "pe": ".pe.bin",
    "elf": ".elf.bin",
    "macho": ".macho.bin",
    "wasm": ".wasm",
    "zip": ".zip",
}


def carve_embedded(data: bytes, output_dir: Path) -> dict:
    """Carve embedded artifacts found after offset zero into output_dir."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = [item for item in find_embedded_artifacts(data) if item["offset"] > 0]
    offsets = [item["offset"] for item in artifacts] + [len(data)]
    carved = []
    for index, artifact in enumerate(artifacts):
        start = artifact["offset"]
        end = offsets[index + 1]
        body = data[start:end][:MAX_CARVE_BYTES]
        digest = hashlib.sha256(body).hexdigest()
        extension = EXTENSIONS.get(artifact["kind"], ".bin")
        name = f"artifact_{index:03d}_{artifact['kind']}_{start:08x}{extension}"
        path = output_dir / name
        path.write_bytes(body)
        carved.append(
            {
                "index": index,
                "kind": artifact["kind"],
                "offset": start,
                "size": len(body),
                "truncated": (end - start) > len(body),
                "sha256": digest,
                "path": str(path),
            }
        )

    manifest = {"count": len(carved), "artifacts": carved}
    (output_dir / "carve_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def carve_file(path: Path, output_dir: Path) -> dict:
    return carve_embedded(Path(path).read_bytes(), output_dir)
