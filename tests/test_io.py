"""Tests for JSON IO helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from razin.io import write_json_atomic


def test_write_json_atomic_cleans_temp_file_on_error(tmp_path: Path) -> None:
    out_path = tmp_path / "report.json"
    temp_prefix = ".tmp-"
    temp_suffix = ".json"

    with pytest.raises(TypeError):
        write_json_atomic(
            path=out_path,
            payload={"bad": object()},
            temp_prefix=temp_prefix,
            temp_suffix=temp_suffix,
        )

    leftovers = [
        item for item in tmp_path.iterdir() if item.name.startswith(temp_prefix) and item.name.endswith(temp_suffix)
    ]
    assert not leftovers
    assert not out_path.exists()
