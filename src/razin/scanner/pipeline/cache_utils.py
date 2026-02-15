"""Cache-related helpers for the scanner pipeline."""

from __future__ import annotations

import logging
from pathlib import Path

from razin.io import file_sha256
from razin.scanner.mcp_remote import resolve_associated_mcp_json
from razin.types import CacheNamespace, CachePayload

logger = logging.getLogger(__name__)


def is_cache_hit(
    entry: object,
    *,
    sha256: str,
    mtime_ns: int,
    mcp_dependency: tuple[str, int, str] | None,
) -> bool:
    """Return True when skill file and MCP dependency signatures match cache entry."""
    if not isinstance(entry, dict):
        return False

    cached_sha256 = entry.get("sha256")
    cached_mtime_ns = entry.get("mtime_ns")
    if not isinstance(cached_sha256, str):
        return False
    if not isinstance(cached_mtime_ns, int):
        return False

    if cached_sha256 != sha256 or cached_mtime_ns != mtime_ns:
        return False

    cached_mcp_path = entry.get("mcp_json_path")
    cached_mcp_mtime_ns = entry.get("mcp_json_mtime_ns")
    cached_mcp_sha256 = entry.get("mcp_json_sha256")

    if mcp_dependency is None:
        return cached_mcp_path is None and cached_mcp_mtime_ns is None and cached_mcp_sha256 is None

    if not isinstance(cached_mcp_path, str):
        return False
    if not isinstance(cached_mcp_mtime_ns, int):
        return False
    if not isinstance(cached_mcp_sha256, str):
        return False

    return (cached_mcp_path, cached_mcp_mtime_ns, cached_mcp_sha256) == mcp_dependency


def resolve_mcp_dependency_signature(
    *,
    path: Path,
    root: Path,
    warnings: list[str],
) -> tuple[str, int, str] | None:
    """Build cache signature tuple for associated ``.mcp.json``, when present."""
    mcp_path = resolve_associated_mcp_json(path, root)
    if mcp_path is None:
        return None

    try:
        mcp_stat = mcp_path.stat()
        mcp_mtime_ns = int(mcp_stat.st_mtime_ns)
        mcp_sha256 = file_sha256(mcp_path)
    except OSError as exc:
        warning = f"Failed to read MCP JSON metadata: {mcp_path} ({exc})"
        warnings.append(warning)
        logger.warning(warning)
        return (str(mcp_path), -1, "")

    return (str(mcp_path), mcp_mtime_ns, mcp_sha256)


def get_or_create_cache_namespace(
    *,
    cache_payload: CachePayload,
    scan_fingerprint: str,
    config_fingerprint: str,
    engine: str,
    rulepack_fingerprint: str,
) -> CacheNamespace:
    """Return an existing cache namespace or create a fresh one."""
    namespaces = cache_payload["namespaces"]
    namespace = namespaces.get(scan_fingerprint)
    if namespace is not None:
        return {
            "scan_fingerprint": scan_fingerprint,
            "config_fingerprint": config_fingerprint,
            "engine": engine,
            "rulepack_fingerprint": rulepack_fingerprint,
            "files": namespace["files"],
        }

    return new_namespace(
        scan_fingerprint=scan_fingerprint,
        config_fingerprint=config_fingerprint,
        engine=engine,
        rulepack_fingerprint=rulepack_fingerprint,
    )


def new_namespace(
    *,
    scan_fingerprint: str,
    config_fingerprint: str,
    engine: str,
    rulepack_fingerprint: str,
) -> CacheNamespace:
    """Create an empty cache namespace payload."""
    return {
        "scan_fingerprint": scan_fingerprint,
        "config_fingerprint": config_fingerprint,
        "engine": engine,
        "rulepack_fingerprint": rulepack_fingerprint,
        "files": {},
    }
