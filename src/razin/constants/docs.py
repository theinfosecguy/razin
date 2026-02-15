"""Constants for SKILL.md doc-surface detectors."""

from __future__ import annotations

import re
from re import Pattern

MCP_PATH_TOKEN: str = "/mcp"

MCP_REQUIRED_SCORE: int = 28
MCP_ENDPOINT_SCORE: int = 70
MCP_DENYLIST_SCORE: int = 90
TOOL_INVOCATION_SCORE: int = 20
DYNAMIC_SCHEMA_SCORE: int = 15
AUTH_CONNECTION_SCORE: int = 45
EXTERNAL_URLS_SCORE: int = 12
AUTH_MIN_HINT_COUNT: int = 2

TOOL_TOKEN_PATTERN: Pattern[str] = re.compile(r"\b[A-Z][A-Z0-9_]{3,}\b")
SERVICE_TOOL_TOKEN_PATTERN: Pattern[str] = re.compile(r"\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+){2,}\b")
SERVICE_TOOL_MIN_TOTAL_LENGTH: int = 15

DYNAMIC_SCHEMA_HINTS: tuple[str, ...] = (
    "discover tools",
    "list tools",
    "tool discovery",
    "schema discovery",
    "inspect schema",
    "describe schema",
    "before executing",
    "before execution",
    "dynamic schema",
)

# Strong hints: language that specifically indicates auth/credential flow.
AUTH_STRONG_HINTS: tuple[str, ...] = (
    "authenticate",
    "authentication",
    "oauth",
    "login",
)

# Weak hints: words commonly found in non-auth contexts (pagination tokens,
# MCP connection language, template "No API keys needed").  These only
# contribute to the hint count when at least one strong hint is also present.
AUTH_WEAK_HINTS: tuple[str, ...] = (
    "api key",
    "token",
    "connect",
    "connection",
    "secret",
)

TOOL_TIER_DESTRUCTIVE_KEYWORDS: tuple[str, ...] = (
    "DELETE",
    "REMOVE",
    "DROP",
    "DESTROY",
    "MERGE",
    "FORCE",
    "PURGE",
)

TOOL_TIER_WRITE_KEYWORDS: tuple[str, ...] = (
    "CREATE",
    "UPDATE",
    "SEND",
    "MODIFY",
    "PATCH",
    "DISPATCH",
    "TRIGGER",
)

TOOL_TIER_DESTRUCTIVE_BONUS: int = 15
TOOL_TIER_WRITE_BONUS: int = 8

TOOL_CONSOLIDATION_MAX_SCORE: int = 50
TOOL_CONSOLIDATION_TOP_N: int = 5

DEFAULT_TOOL_PREFIXES: tuple[str, ...] = ("RUBE_", "MCP_")

NEGATION_PREFIXES: tuple[str, ...] = (
    "no ",
    "not ",
    "without ",
    "don't need",
    "doesn't require",
    "not require",
    "not needed",
    "no need for",
)

DEFAULT_SERVICE_TOOL_PREFIXES: tuple[str, ...] = (
    "AIRTABLE",
    "AWS",
    "AZURE",
    "DISCORD",
    "GITHUB",
    "GITLAB",
    "GOOGLE",
    "HUBSPOT",
    "JIRA",
    "LINEAR",
    "MAILCHIMP",
    "NOTION",
    "OPENAI",
    "SALESFORCE",
    "SENDGRID",
    "SHOPIFY",
    "SLACK",
    "STRIPE",
    "SUPABASE",
    "TELEGRAM",
    "TWILIO",
    "ZENDESK",
)
