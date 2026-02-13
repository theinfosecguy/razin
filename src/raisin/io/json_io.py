"""JSON read/write helpers with atomic persistence."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path


def load_json_file(path: Path) -> object:
    """Load and parse JSON from disk."""
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(
    *,
    path: Path,
    payload: object,
    temp_prefix: str,
    temp_suffix: str,
) -> None:
    """Persist JSON atomically by writing to a temp file then renaming."""
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=temp_prefix,
            suffix=temp_suffix,
            delete=False,
        ) as handle:
            temp_name = handle.name
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except Exception:
        if temp_name:
            with suppress(FileNotFoundError):
                Path(temp_name).unlink()
        raise

    assert temp_name is not None
    os.replace(temp_name, path)
