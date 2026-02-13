"""File-level helpers for hashing and generic utilities."""

from __future__ import annotations

import hashlib
from pathlib import Path

from razin.constants.cache import FILE_HASH_CHUNK_SIZE


def file_sha256(path: Path) -> str:
    """Return SHA-256 hex digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(FILE_HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()
