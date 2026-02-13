"""Tests for shared detector helpers (normalize_url, extract_domain, etc.)."""

from __future__ import annotations

from razin.detectors.common import extract_domain, normalize_url


class TestUrlNormalization:
    """normalize_url should strip trailing markdown punctuation."""

    def test_strip_trailing_backtick(self) -> None:
        assert normalize_url("https://rube.app/mcp`") == "https://rube.app/mcp"

    def test_strip_trailing_paren(self) -> None:
        assert normalize_url("https://composio.dev/toolkits/ably)") == ("https://composio.dev/toolkits/ably")

    def test_strip_trailing_asterisk(self) -> None:
        assert normalize_url("https://composio.dev)*") == "https://composio.dev"

    def test_strip_trailing_period(self) -> None:
        assert normalize_url("https://example.com/path.") == ("https://example.com/path")

    def test_strip_multiple_trailing_chars(self) -> None:
        assert normalize_url("https://example.com/path)*.") == ("https://example.com/path")

    def test_no_strip_for_clean_url(self) -> None:
        assert normalize_url("https://example.com/path") == ("https://example.com/path")

    def test_extract_domain_clean_after_normalization(self) -> None:
        """Trailing paren no longer corrupts hostname."""
        assert extract_domain("https://composio.dev/toolkits/x)") == "composio.dev"

    def test_extract_domain_backtick_url(self) -> None:
        assert extract_domain("https://rube.app/mcp`") == "rube.app"
