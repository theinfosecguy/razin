"""Cache loading and persistence for scan results."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from raisin.constants.cache import CACHE_TEMP_PREFIX, CACHE_TEMP_SUFFIX, CACHE_VERSION, LEGACY_CACHE_ENGINE
from raisin.io import load_json_file, write_json_atomic
from raisin.types import CacheFileEntry, CacheNamespace, CachePayload


def new_cache() -> CachePayload:
    """Return an empty cache payload."""
    return {
        "version": CACHE_VERSION,
        "namespaces": {},
    }


def load_cache(cache_path: Path) -> CachePayload:
    """Load cache file if valid, otherwise return a new cache payload."""
    if not cache_path.is_file():
        return new_cache()

    try:
        payload = load_json_file(cache_path)
    except (OSError, ValueError):
        return new_cache()

    if not isinstance(payload, dict):
        return new_cache()

    version = payload.get("version")
    if version == CACHE_VERSION:
        return _load_v3_payload(payload)
    if version == 2:
        return _migrate_v2_payload(payload)
    return new_cache()


def build_scan_fingerprint(
    *,
    config_fingerprint: str,
    engine: str,
    rulepack_fingerprint: str,
) -> str:
    """Return stable scan fingerprint across config, engine, and rulepack."""
    payload = {
        "config_fingerprint": config_fingerprint,
        "engine": engine,
        "rulepack_fingerprint": rulepack_fingerprint,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _load_v3_payload(payload: dict[object, object]) -> CachePayload:
    raw_namespaces = payload.get("namespaces")
    if not isinstance(raw_namespaces, dict):
        return new_cache()

    namespaces: dict[str, CacheNamespace] = {}
    for key, value in raw_namespaces.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        namespace = _normalize_namespace(value, fallback_scan_fingerprint=key)
        namespaces[key] = namespace

    return {
        "version": CACHE_VERSION,
        "namespaces": namespaces,
    }


def save_cache(cache_path: Path, payload: CachePayload) -> None:
    """Persist cache to disk atomically."""
    write_json_atomic(
        path=cache_path,
        payload=payload,
        temp_prefix=CACHE_TEMP_PREFIX,
        temp_suffix=CACHE_TEMP_SUFFIX,
    )


def _migrate_v2_payload(payload: dict[object, object]) -> CachePayload:
    config_fingerprint = payload.get("config_fingerprint")
    raw_files = payload.get("files")

    if not isinstance(config_fingerprint, str):
        config_fingerprint = ""

    files = _normalize_files(raw_files)
    if not config_fingerprint and not files:
        return new_cache()

    rulepack_fingerprint = ""
    scan_fingerprint = build_scan_fingerprint(
        config_fingerprint=config_fingerprint,
        engine=LEGACY_CACHE_ENGINE,
        rulepack_fingerprint=rulepack_fingerprint,
    )
    return {
        "version": CACHE_VERSION,
        "namespaces": {
            scan_fingerprint: {
                "scan_fingerprint": scan_fingerprint,
                "config_fingerprint": config_fingerprint,
                "engine": LEGACY_CACHE_ENGINE,
                "rulepack_fingerprint": rulepack_fingerprint,
                "files": files,
            }
        },
    }


def _normalize_namespace(value: dict[object, object], *, fallback_scan_fingerprint: str) -> CacheNamespace:
    scan_fingerprint = value.get("scan_fingerprint")
    config_fingerprint = value.get("config_fingerprint")
    engine = value.get("engine")
    rulepack_fingerprint = value.get("rulepack_fingerprint")

    if not isinstance(scan_fingerprint, str) or not scan_fingerprint:
        scan_fingerprint = fallback_scan_fingerprint
    if not isinstance(config_fingerprint, str):
        config_fingerprint = ""
    if not isinstance(engine, str):
        engine = ""
    if not isinstance(rulepack_fingerprint, str):
        rulepack_fingerprint = ""

    return {
        "scan_fingerprint": scan_fingerprint,
        "config_fingerprint": config_fingerprint,
        "engine": engine,
        "rulepack_fingerprint": rulepack_fingerprint,
        "files": _normalize_files(value.get("files")),
    }


def _normalize_files(raw_files: object) -> dict[str, CacheFileEntry]:
    if not isinstance(raw_files, dict):
        return {}

    files: dict[str, CacheFileEntry] = {}
    for key, value in raw_files.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue

        mtime_ns = value.get("mtime_ns")
        sha256 = value.get("sha256")
        skill_name = value.get("skill_name")
        findings = value.get("findings")

        if not isinstance(mtime_ns, int):
            continue
        if not isinstance(sha256, str):
            continue
        if not isinstance(skill_name, str):
            continue
        if not isinstance(findings, list):
            continue

        files[key] = {
            "mtime_ns": mtime_ns,
            "sha256": sha256,
            "skill_name": skill_name,
            "findings": [finding for finding in findings if isinstance(finding, dict)],
        }
    return files
