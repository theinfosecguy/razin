"""Pre-publish guard: ensures pyproject.toml version is valid and unpublished.

Checks performed:
1. Reads [project].version from pyproject.toml.
2. If GITHUB_REF is a tag (refs/tags/v*), verifies tag matches pyproject version.
3. Queries PyPI JSON API and fails if the version already exists.

Exit codes:
  0 - version is safe to publish.
  1 - validation failed (duplicate, mismatch, or parse error).
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

PYPI_PACKAGE = "razin"
PYPI_API_URL = f"https://pypi.org/pypi/{PYPI_PACKAGE}/json"
PYPROJECT_PATH = Path(__file__).resolve().parent.parent / "pyproject.toml"


def read_pyproject_version(path: Path) -> str:
    """Extract version string from pyproject.toml without a TOML library."""
    in_project = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[project]":
            in_project = True
            continue
        if stripped.startswith("[") and in_project:
            break
        if in_project and stripped.startswith("version"):
            _, _, value = stripped.partition("=")
            return value.strip().strip('"').strip("'")
    print("ERROR: could not read version from pyproject.toml", file=sys.stderr)
    sys.exit(1)


def check_tag_match(version: str) -> None:
    """If running in a tag-push context, ensure tag matches pyproject version."""
    import os

    ref = os.environ.get("GITHUB_REF", "")
    if not ref.startswith("refs/tags/v"):
        return
    tag_version = ref.removeprefix("refs/tags/v")
    if tag_version != version:
        print(
            f"ERROR: git tag v{tag_version} does not match pyproject.toml version {version}",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"OK: tag v{tag_version} matches pyproject.toml version {version}")


def check_pypi_not_published(version: str) -> None:
    """Fail if version already exists on PyPI."""
    try:
        req = urllib.request.Request(PYPI_API_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print(f"OK: package {PYPI_PACKAGE} not yet on PyPI; version {version} is safe to publish")
            return
        print(f"ERROR: PyPI API returned HTTP {exc.code}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: failed to reach PyPI API: {exc}", file=sys.stderr)
        sys.exit(1)

    published = set(data.get("releases", {}).keys())
    if version in published:
        print(f"ERROR: version {version} is already published on PyPI", file=sys.stderr)
        sys.exit(1)
    print(f"OK: version {version} is not yet on PyPI ({len(published)} existing releases)")


def main() -> None:
    version = read_pyproject_version(PYPROJECT_PATH)
    print(f"pyproject.toml version: {version}")
    check_tag_match(version)
    check_pypi_not_published(version)
    print(f"All checks passed. Safe to publish {PYPI_PACKAGE}=={version}")


if __name__ == "__main__":
    main()
