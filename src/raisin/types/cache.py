"""Typed cache payload structures."""

from __future__ import annotations

from typing import TypedDict

from raisin.types.common import JsonObject


class CacheFileEntry(TypedDict):
    """Cache metadata for a single scanned file."""

    mtime_ns: int
    sha256: str
    skill_name: str
    findings: list[JsonObject]


class CacheNamespace(TypedDict):
    """Engine/profile scoped namespace inside the cache payload."""

    scan_fingerprint: str
    config_fingerprint: str
    engine: str
    rulepack_fingerprint: str
    files: dict[str, CacheFileEntry]


class CachePayload(TypedDict):
    """Top-level cache payload persisted to disk."""

    version: int
    namespaces: dict[str, CacheNamespace]
