"""Tests for configuration loading and fingerprinting."""

from __future__ import annotations

from pathlib import Path

import pytest

from razin.config import (
    DetectorConfig,
    RaisinConfig,
    config_fingerprint,
    effective_detector_ids,
    load_config,
)
from razin.constants.config import DEFAULT_DETECTORS
from razin.constants.domains import DEFAULT_ALLOWLISTED_DOMAINS
from razin.exceptions import ConfigError


def test_load_config_defaults_when_missing(tmp_path: Path) -> None:
    loaded = load_config(tmp_path)

    assert loaded.skill_globs
    assert loaded.max_file_mb > 0


def test_load_config_rejects_bool_max_file_mb(tmp_path: Path) -> None:
    config_path = tmp_path / "razin.yaml"
    config_path.write_text("max_file_mb: true\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="max_file_mb"):
        load_config(tmp_path, config_path)


def test_load_config_error_includes_key_name(tmp_path: Path) -> None:
    config_path = tmp_path / "razin.yaml"
    config_path.write_text("allowlist_domains: 123\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="allowlist_domains"):
        load_config(tmp_path, config_path)


@pytest.mark.parametrize(
    ("yaml_content", "expected_match"),
    [
        ("profile: paranoid\n", "profile"),
        ("ignore_default_allowlist: maybe\n", "ignore_default_allowlist"),
    ],
    ids=["invalid_profile", "non_bool_ignore_allowlist"],
)
def test_load_config_rejects_invalid_field_values(tmp_path: Path, yaml_content: str, expected_match: str) -> None:
    config_path = tmp_path / "razin.yaml"
    config_path.write_text(yaml_content, encoding="utf-8")

    with pytest.raises(ConfigError, match=expected_match):
        load_config(tmp_path, config_path)


def test_effective_detector_ids_respects_disabled() -> None:
    config = RaisinConfig(detectors=DetectorConfig(enabled=DEFAULT_DETECTORS, disabled=("SECRET_REF",)))

    detector_ids = effective_detector_ids(config)

    assert "SECRET_REF" not in detector_ids
    assert "NET_RAW_IP" in detector_ids


def test_config_fingerprint_is_stable() -> None:
    config = RaisinConfig(
        allowlist_domains=("api.openai.com",),
        denylist_domains=("evil.example.net",),
        mcp_allowlist_domains=("rube.app",),
        mcp_denylist_domains=("blocked.example.com",),
        tool_prefixes=("RUBE_", "MCP_"),
        detectors=DetectorConfig(enabled=("NET_RAW_IP",), disabled=()),
        typosquat_baseline=("openai-helper",),
        skill_globs=("**/*.yaml",),
        max_file_mb=2,
    )

    first = config_fingerprint(config)
    second = config_fingerprint(config)

    assert first == second


def test_load_config_reads_mcp_and_tool_prefixes(tmp_path: Path) -> None:
    config_path = tmp_path / "razin.yaml"
    config_path.write_text(
        "\n".join(
            [
                "mcp_allowlist_domains:",
                "  - rube.app",
                "mcp_denylist_domains:",
                "  - blocked.example.com",
                "tool_prefixes:",
                "  - RUBE_",
                "  - MCP_",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    loaded = load_config(tmp_path, config_path)

    assert loaded.mcp_allowlist_domains == ("rube.app",)
    assert loaded.mcp_denylist_domains == ("blocked.example.com",)
    assert loaded.tool_prefixes == ("RUBE_", "MCP_")


def test_default_profile_is_balanced() -> None:
    config = RaisinConfig()
    assert config.profile == "balanced"


def test_load_config_reads_profile(tmp_path: Path) -> None:
    config_path = tmp_path / "razin.yaml"
    config_path.write_text("profile: strict\n", encoding="utf-8")
    loaded = load_config(tmp_path, config_path)
    assert loaded.profile == "strict"


def test_profile_changes_fingerprint() -> None:
    strict = RaisinConfig(profile="strict")
    balanced = RaisinConfig(profile="balanced")
    assert config_fingerprint(strict) != config_fingerprint(balanced)


def test_profile_aggregate_min_rule_score() -> None:
    strict = RaisinConfig(profile="strict")
    balanced = RaisinConfig(profile="balanced")
    audit = RaisinConfig(profile="audit")
    assert strict.aggregate_min_rule_score < balanced.aggregate_min_rule_score
    assert audit.aggregate_min_rule_score > 100  # nothing contributes


def test_profile_suppress_local_hosts() -> None:
    strict = RaisinConfig(profile="strict")
    balanced = RaisinConfig(profile="balanced")
    assert strict.suppress_local_hosts is False
    assert balanced.suppress_local_hosts is True


def test_default_allowlist_applies_when_not_ignored() -> None:
    config = RaisinConfig()
    assert "github.com" in config.effective_allowlist_domains
    assert set(DEFAULT_ALLOWLISTED_DOMAINS).issubset(set(config.effective_allowlist_domains))


def test_load_config_merges_custom_allowlist_with_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / "razin.yaml"
    config_path.write_text(
        "allowlist_domains:\n" "  - internal.example.com\n",
        encoding="utf-8",
    )

    loaded = load_config(tmp_path, config_path)

    assert loaded.allowlist_domains == ("internal.example.com",)
    assert "internal.example.com" in loaded.effective_allowlist_domains
    assert "github.com" in loaded.effective_allowlist_domains


def test_load_config_can_ignore_default_allowlist(tmp_path: Path) -> None:
    config_path = tmp_path / "razin.yaml"
    config_path.write_text(
        "ignore_default_allowlist: true\n" "allowlist_domains:\n" "  - internal.example.com\n",
        encoding="utf-8",
    )

    loaded = load_config(tmp_path, config_path)

    assert loaded.ignore_default_allowlist is True
    assert loaded.effective_allowlist_domains == ("internal.example.com",)
