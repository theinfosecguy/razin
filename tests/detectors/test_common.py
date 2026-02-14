"""Tests for shared detector helpers (normalize_url, extract_domain, etc.)."""

from __future__ import annotations

import pytest

from razin.detectors.common import extract_domain, normalize_url


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
