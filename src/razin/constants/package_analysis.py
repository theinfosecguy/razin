"""Constants for bounded, non-executing package analysis."""

from __future__ import annotations

PACKAGE_RULE_IDS: tuple[str, ...] = (
    "PACKAGE_SENSITIVE_NETWORK_FLOW",
    "PACKAGE_DATA_EXFILTRATION",
    "PACKAGE_REMOTE_CODE_EXECUTION",
    "PACKAGE_INVENTORY",
    "INCOMPLETE_SCAN",
    "DYNAMIC_ANALYSIS_REQUIRED",
    "MUTABLE_REMOTE_REFERENCE",
    "KNOWN_BAD_DOMAIN",
    "KNOWN_BAD_FILE_HASH",
    "KNOWN_BAD_INDICATOR",
)

ANALYZED_SCRIPT_SUFFIXES: frozenset[str] = frozenset(
    {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".sh", ".bash", ".zsh"}
)

ARCHIVE_SUFFIXES: tuple[str, ...] = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".rar",
    ".7z",
    ".jar",
    ".whl",
)

UNSUPPORTED_EXECUTABLE_SUFFIXES: frozenset[str] = frozenset(
    {".exe", ".dll", ".dylib", ".so", ".wasm", ".class", ".pyc", ".pyo", ".node"}
)

UNSUPPORTED_SOURCE_SUFFIXES: frozenset[str] = frozenset(
    {".go", ".rs", ".rb", ".php", ".java", ".kt", ".kts", ".swift", ".ps1", ".lua", ".pl", ".r"}
)

TEXT_SUFFIXES: frozenset[str] = frozenset(
    {
        "",
        ".md",
        ".mdx",
        ".txt",
        ".json",
        ".jsonl",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".xml",
        ".csv",
        ".lock",
        ".env",
        *ANALYZED_SCRIPT_SUFFIXES,
    }
)

IGNORED_PACKAGE_DIRECTORIES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "node_modules",
        "venv",
    }
)

MANIFEST_FILENAMES: frozenset[str] = frozenset(
    {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "requirements.txt",
        "pipfile",
        "pipfile.lock",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
    }
)

DEFAULT_PACKAGE_MAX_FILES: int = 256
DEFAULT_PACKAGE_MAX_DIRECTORIES: int = 128
DEFAULT_PACKAGE_MAX_TOTAL_MB: int = 16
DEFAULT_PACKAGE_MAX_FILE_MB: int = 2
DEFAULT_PACKAGE_MAX_FINDINGS_PER_RULE: int = 20
PACKAGE_COVERAGE_DIGEST_VERSION: int = 2
MAX_IOC_ENTRIES_PER_KIND: int = 256
MAX_IOC_INDICATOR_LENGTH: int = 256
SUSPICIOUS_COLLECTION_DOMAINS: frozenset[str] = frozenset(
    {
        "webhook.site",
        "requestbin.com",
        "pipedream.net",
        "hookbin.com",
        "beeceptor.com",
    }
)
