"""Tests for shared detector helpers (normalize_url, extract_domain, etc.)."""

from __future__ import annotations

import pytest

from razin.detectors.common import extract_domain, is_allowlisted, normalize_url


@pytest.mark.parametrize(
    ("raw_url", "expected"),
    [
        ("https://rube.app/mcp`", "https://rube.app/mcp"),
        ("https://composio.dev/toolkits/ably)", "https://composio.dev/toolkits/ably"),
        ("https://composio.dev)*", "https://composio.dev"),
        ("https://example.com/path.", "https://example.com/path"),
        ("https://example.com/path)*.", "https://example.com/path"),
        ("https://example.com/path", "https://example.com/path"),
    ],
    ids=["backtick", "paren", "asterisk", "period", "multiple", "clean"],
)
def test_normalize_url_strips_trailing_punctuation(raw_url: str, expected: str) -> None:
    assert normalize_url(raw_url) == expected


@pytest.mark.parametrize(
    ("raw_url", "expected_domain"),
    [
        ("https://composio.dev/toolkits/x)", "composio.dev"),
        ("https://rube.app/mcp`", "rube.app"),
    ],
    ids=["trailing-paren", "trailing-backtick"],
)
def test_extract_domain_after_normalization(raw_url: str, expected_domain: str) -> None:
    assert extract_domain(raw_url) == expected_domain


def test_is_allowlisted_default_matches_subdomains() -> None:
    """Default (non-strict) mode matches subdomains of allowlisted domains."""
    allowlist = ("github.com", "example.com")
    assert is_allowlisted("github.com", allowlist) is True
    assert is_allowlisted("docs.github.com", allowlist) is True
    assert is_allowlisted("api.example.com", allowlist) is True
    assert is_allowlisted("unknown.io", allowlist) is False


def test_is_allowlisted_strict_rejects_subdomains() -> None:
    """Strict mode only matches exact domains, not subdomains."""
    allowlist = ("github.com", "example.com")
    assert is_allowlisted("github.com", allowlist, strict=True) is True
    assert is_allowlisted("docs.github.com", allowlist, strict=True) is False
    assert is_allowlisted("api.example.com", allowlist, strict=True) is False


def test_is_allowlisted_empty_allowlist() -> None:
    """Empty allowlist never matches."""
    assert is_allowlisted("github.com", ()) is False
    assert is_allowlisted("github.com", (), strict=True) is False
