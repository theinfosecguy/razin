"""Detector-specific constants and thresholds."""

from __future__ import annotations

import re
from re import Pattern

URL_PATTERN: Pattern[str] = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_PATTERN: Pattern[str] = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
BRACKET_IPV6_PATTERN: Pattern[str] = re.compile(r"\[([0-9A-Fa-f:]+)\]")
ENV_REF_PATTERN: Pattern[str] = re.compile(
    r"(\$\{[A-Z0-9_]+\}|\$[A-Z_][A-Z0-9_]*|\{\{\s*secrets\.[^}]+\}\}|os\.getenv\()",
    re.IGNORECASE,
)
BASE64_PATTERN: Pattern[str] = re.compile(r"^[A-Za-z0-9+/=_-]{80,}$")
SECRET_PLACEHOLDER_VALUE_PATTERN: Pattern[str] = re.compile(
    r"(?:\byour[-_]|<\s*placeholder\s*>|\bchangeme\b|\btodo\b|\bxxx+\b|\breplace[-_])",
    re.IGNORECASE,
)

SECRET_KEYWORDS: tuple[str, ...] = (
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "credential",
    "private_key",
    "auth",
)
EXEC_FIELD_NAMES: frozenset[str] = frozenset({"command", "script", "exec", "shell", "run"})
SCRIPT_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".sh",
        ".bash",
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".ps1",
        ".rb",
        ".php",
        ".go",
        ".rs",
        ".java",
    }
)

OPAQUE_MIN_LENGTH: int = 80
OPAQUE_LONG_LENGTH: int = 180
OPAQUE_MIN_ENTROPY: float = 4.5

TYPOSQUAT_MAX_DISTANCE: int = 2
TYPOSQUAT_MIN_NAME_LENGTH: int = 5

NET_RAW_IP_PUBLIC_SCORE: int = 82
NET_RAW_IP_NON_PUBLIC_SCORE: int = 50
NET_DENYLIST_DOMAIN_SCORE: int = 80
NET_UNKNOWN_DOMAIN_ALLOWLIST_SCORE: int = 55
NET_UNKNOWN_DOMAIN_OPEN_SCORE: int = 35

SECRET_KEY_SCORE: int = 74
SECRET_ENV_REF_SCORE: int = 60
EXEC_FIELDS_SCORE: int = 72
OPAQUE_BLOB_SCORE: int = 54
TYPOSQUAT_SCORE: int = 76
BUNDLED_SCRIPTS_SCORE: int = 58

# Hosts and TLDs always suppressed by NET_UNKNOWN_DOMAIN — these represent
# local/dev/documentation examples, not real external risk.
LOCAL_DEV_HOSTS: frozenset[str] = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
    }
)

LOCAL_DEV_TLDS: tuple[str, ...] = (
    ".local",
    ".test",
    ".example",
    ".invalid",
    ".internal",
    ".localhost",
)

# Full domains reserved for documentation (RFC 2606 / RFC 6761).
RESERVED_EXAMPLE_DOMAINS: frozenset[str] = frozenset(
    {
        "example.com",
        "example.net",
        "example.org",
        "www.example.com",
        "www.example.net",
        "www.example.org",
    }
)
