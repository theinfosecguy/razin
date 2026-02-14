"""Constants for MCP JSON remote endpoint checks."""

from __future__ import annotations

MCP_JSON_FILENAME: str = ".mcp.json"

MCP_REMOTE_NON_HTTPS_RULE_ID: str = "MCP_REMOTE_NON_HTTPS"
MCP_REMOTE_RAW_IP_RULE_ID: str = "MCP_REMOTE_RAW_IP"
MCP_REMOTE_DENYLIST_RULE_ID: str = "MCP_REMOTE_DENYLIST"

MCP_REMOTE_NON_HTTPS_SCORE: int = 52
MCP_REMOTE_RAW_IP_SCORE: int = 82
MCP_REMOTE_DENYLIST_SCORE: int = 90

MCP_REMOTE_RULE_PRIORITY: dict[str, int] = {
    MCP_REMOTE_NON_HTTPS_RULE_ID: 1,
    MCP_REMOTE_RAW_IP_RULE_ID: 2,
    MCP_REMOTE_DENYLIST_RULE_ID: 3,
}

MCP_NON_HTTPS_LOCAL_EXCEPTIONS: frozenset[str] = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
    }
)
