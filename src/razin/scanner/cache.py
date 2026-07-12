"""Cache loading and persistence for scan results."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from razin.constants.cache import CACHE_TEMP_PREFIX, CACHE_TEMP_SUFFIX, CACHE_VERSION
from razin.io import load_json_file, write_json_atomic
from razin.types import CacheFileEntry, CacheNamespace, CachePayload


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
    return new_cache()


def build_scan_fingerprint(
    *,
    config_fingerprint: str,
    engine: str,
    rulepack_fingerprint: str,
    executed_rule_ids: tuple[str, ...] = (),
) -> str:
    """Return stable scan fingerprint across config, engine, rules, and rulepack."""
    payload = {
        "config_fingerprint": config_fingerprint,
        "engine": engine,
        "rulepack_fingerprint": rulepack_fingerprint,
        "executed_rule_ids": list(executed_rule_ids),
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
        mcp_json_path = value.get("mcp_json_path")
        mcp_json_mtime_ns = value.get("mcp_json_mtime_ns")
        mcp_json_sha256 = value.get("mcp_json_sha256")
        package_sha256 = value.get("package_sha256")
        coverage_status = value.get("coverage_status")
        coverage_reasons = value.get("coverage_reasons")

        if not isinstance(mtime_ns, int):
            continue
        if not isinstance(sha256, str):
            continue
        if not isinstance(skill_name, str):
            continue
        if not isinstance(findings, list):
            continue

        entry: CacheFileEntry = {
            "mtime_ns": mtime_ns,
            "sha256": sha256,
            "skill_name": skill_name,
            "findings": [finding for finding in findings if isinstance(finding, dict)],
        }
        if isinstance(mcp_json_path, str):
            entry["mcp_json_path"] = mcp_json_path
        if isinstance(mcp_json_mtime_ns, int):
            entry["mcp_json_mtime_ns"] = mcp_json_mtime_ns
        if isinstance(mcp_json_sha256, str):
            entry["mcp_json_sha256"] = mcp_json_sha256
        if isinstance(package_sha256, str):
            entry["package_sha256"] = package_sha256
        if coverage_status in {"complete", "incomplete", "not-evaluated"}:
            entry["coverage_status"] = coverage_status  # type: ignore[typeddict-item]
        if isinstance(coverage_reasons, list) and all(isinstance(reason, str) for reason in coverage_reasons):
            entry["coverage_reasons"] = sorted(set(coverage_reasons))

        files[key] = entry
    return files
