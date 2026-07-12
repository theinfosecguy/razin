"""Tests for cache read/write behavior."""

from __future__ import annotations

from pathlib import Path

from razin.scanner.cache import build_scan_fingerprint, load_cache, new_cache, save_cache


def test_cache_roundtrip(tmp_path: Path) -> None:
    cache_path = tmp_path / ".razin-cache.json"
    payload = new_cache()
    scan_fingerprint = build_scan_fingerprint(
        config_fingerprint="abc123",
        engine="dsl",
        rulepack_fingerprint="rules-v1",
    )
    payload["namespaces"][scan_fingerprint] = {
        "scan_fingerprint": scan_fingerprint,
        "config_fingerprint": "abc123",
        "engine": "dsl",
        "rulepack_fingerprint": "rules-v1",
        "files": {},
    }
    payload["namespaces"][scan_fingerprint]["files"]["/tmp/x.yaml"] = {
        "mtime_ns": 123,
        "sha256": "deadbeef",
        "skill_name": "skill-a",
        "findings": [],
    }

    save_cache(cache_path, payload)
    loaded = load_cache(cache_path)

    assert loaded == payload


def test_scan_fingerprint_changes_with_effective_rule_selection() -> None:
    enabled = build_scan_fingerprint(
        config_fingerprint="config",
        engine="dsl",
        rulepack_fingerprint="rules",
        executed_rule_ids=("PACKAGE_DATA_EXFILTRATION",),
    )
    disabled = build_scan_fingerprint(
        config_fingerprint="config",
        engine="dsl",
        rulepack_fingerprint="rules",
        executed_rule_ids=(),
    )

    assert enabled != disabled


def test_cache_invalid_payload_falls_back(tmp_path: Path) -> None:
    cache_path = tmp_path / ".razin-cache.json"
    cache_path.write_text('{"version": 999, "namespaces": "bad"}', encoding="utf-8")

    loaded = load_cache(cache_path)

    assert loaded["namespaces"] == {}


def test_cache_invalidates_v2_payload(tmp_path: Path) -> None:
    cache_path = tmp_path / ".razin-cache.json"
    cache_path.write_text(
        (
            '{"version":2,"config_fingerprint":"abc123","files":'
            '{"x":{"mtime_ns":1,"sha256":"a","skill_name":"s","findings":[]}}}'
        ),
        encoding="utf-8",
    )

    loaded = load_cache(cache_path)

    assert loaded["version"] == 4
    assert loaded["namespaces"] == {}
