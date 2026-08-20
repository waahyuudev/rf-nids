"""Reproducible file and dataset identity helpers."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Return the SHA-256 digest of a file without loading it all into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def dataset_identity(paths: Sequence[Path]) -> dict[str, Any]:
    """Hash each source file and their ordered manifest."""
    files = [
        {"path": str(path), "size_bytes": path.stat().st_size, "sha256": sha256_file(path)}
        for path in paths
    ]
    manifest = hashlib.sha256()
    for item in files:
        manifest.update(
            f"{item['path']}\0{item['size_bytes']}\0{item['sha256']}\n".encode("utf-8")
        )
    return {"algorithm": "sha256", "manifest_sha256": manifest.hexdigest(), "files": files}

