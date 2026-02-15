"""Domain allowlist constants."""

from __future__ import annotations

DEFAULT_ALLOWLISTED_DOMAINS: tuple[str, ...] = (
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "npmjs.com",
    "pypi.org",
    "docs.python.org",
    "developer.mozilla.org",
    "wikipedia.org",
    "modelcontextprotocol.io",
    "anthropic.com",
    "openai.com",
    # RFC 2606 reserved example domains — never real external risk.
    "example.com",
    "example.org",
    "example.net",
    # Infrastructure CDN / hosting domains — badges, raw content, etc.
    "raw.githubusercontent.com",
    "img.shields.io",
)
