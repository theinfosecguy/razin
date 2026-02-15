"""Frozen dataclasses for the scanner subsystem."""

from __future__ import annotations

from dataclasses import dataclass

from razin.model import Evidence


@dataclass(frozen=True)
class McpRemoteEndpoint:
    """Resolved MCP server remote endpoint information."""

    server_name: str
    endpoint_url: str
    endpoint_key: str
    host: str
    scheme: str
    is_ip: bool
    is_public_ip: bool
    evidence: Evidence
