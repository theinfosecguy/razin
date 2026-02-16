"""Detector-specific constants and thresholds."""

from __future__ import annotations

import re
from re import Pattern

ZERO_WIDTH_CHARS: frozenset[int] = frozenset(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x2060,  # WORD JOINER
        0x2061,  # FUNCTION APPLICATION
        0x2062,  # INVISIBLE TIMES
        0x2063,  # INVISIBLE SEPARATOR
        0x2064,  # INVISIBLE PLUS
    }
)

EMBEDDED_BOM_CODEPOINT: int = 0xFEFF

HTML_COMMENT_PATTERN: Pattern[str] = re.compile(
    r"<!--(.*?)-->",
    re.DOTALL,
)

HIDDEN_INSTRUCTION_PHRASES: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all instructions",
    "disregard instructions",
    "disregard previous",
    "override instructions",
    "override previous",
    "inject instructions",
    "do not reveal",
    "do not disclose",
    "exfiltrate data",
    "exfiltrate information",
    "exfiltrate conversation",
    "exfiltrate history",
    "exfiltrate session",
    "exfiltrate credentials",
    "exfiltrate secrets",
    "exfiltrate the",
    "send data to",
    "upload data to",
    "send to http",
    "post to http",
    "forward data to",
    "bypass security",
    "bypass restrictions",
    "bypass safety",
    "hidden instruction",
    "system prompt override",
    "you are now",
    "pretend you are",
    "act as if",
    "do not mention",
    "do not tell",
    "do not say",
    "do not show",
    "do not log",
    "keep this secret",
    "keep this hidden",
    "never mention",
    "never reveal",
    "secretly",
    "silently",
    "covertly",
    "without telling",
    "without informing",
    "without the user knowing",
)

HOMOGLYPH_CONFUSABLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x0400, 0x04FF),  # Cyrillic
    (0x0370, 0x03FF),  # Greek
    (0x2100, 0x214F),  # Letterlike Symbols
    (0xFF00, 0xFFEF),  # Fullwidth Forms
)

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
NET_DOC_DOMAIN_SCORE: int = 15

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

RULE_ID_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z][A-Z0-9_]+$")

TRAILING_PUNCT_RE: re.Pattern[str] = re.compile(r"[)`*.,;:!?\]]+$")

UPPERCASE_TOKEN_PATTERN: re.Pattern[str] = re.compile(
    r"\b[A-Z\u0370-\u03FF\u0400-\u04FF\u2100-\u214F\uFF00-\uFFEF]"
    r"[A-Z0-9_\u0370-\u03FF\u0400-\u04FF\u2100-\u214F\uFF00-\uFFEF]{2,}\b",
)

PROSE_MIN_WORDS: int = 3

# Patterns that look like env-var references but are API operators or
# non-secret variable names (e.g., MongoDB $set, Amplitude $add).
NON_SECRET_ENV_OPERATORS: frozenset[str] = frozenset(
    {
        "$add",
        "$set",
        "$setonce",
        "$append",
        "$prepend",
        "$remove",
        "$unset",
        "$union",
        "$delete",
        "$inc",
        "$push",
        "$pull",
        "$pop",
        "$rename",
        "$min",
        "$max",
        "$mul",
        "$bit",
    }
)

# Secret-like keywords that, when found in an env-var name, confirm it as
# a genuine secret reference.
SECRET_ENV_KEYWORDS: tuple[str, ...] = (
    "key",
    "token",
    "secret",
    "password",
    "credential",
    "auth",
    "private",
    "passwd",
    "api_key",
    "apikey",
)
