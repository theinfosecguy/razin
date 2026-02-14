"""MCP JSON remote endpoint checks with relevance gating and precedence suppression."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from razin.config import RazinConfig
from razin.constants.mcp import (
    MCP_JSON_FILENAME,
    MCP_NON_HTTPS_LOCAL_EXCEPTIONS,
    MCP_REMOTE_DENYLIST_RULE_ID,
    MCP_REMOTE_DENYLIST_SCORE,
    MCP_REMOTE_NON_HTTPS_RULE_ID,
    MCP_REMOTE_NON_HTTPS_SCORE,
    MCP_REMOTE_RAW_IP_RULE_ID,
    MCP_REMOTE_RAW_IP_SCORE,
    MCP_REMOTE_RULE_PRIORITY,
)
from razin.detectors.common import is_denylisted
from razin.model import Evidence, FindingCandidate, ParsedSkillDocument


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


def collect_mcp_remote_candidates(
    *,
    parsed: ParsedSkillDocument,
    root: Path,
    config: RazinConfig,
) -> tuple[list[FindingCandidate], list[str]]:
    """Collect MCP remote findings for referenced MCP server URLs only."""
    required_servers = _extract_required_mcp_servers(parsed)
    if not required_servers:
        return [], []

    mcp_json_path = resolve_associated_mcp_json(parsed.file_path, root)
    if mcp_json_path is None:
        return [], []

    try:
        endpoints = parse_referenced_mcp_endpoints(mcp_json_path, required_servers)
    except ValueError as exc:
        warning = f"Parse error in {mcp_json_path}: {exc}"
        return [], [warning]

    if not endpoints:
        return [], []

    raw_candidates: list[tuple[str, FindingCandidate]] = []
    for endpoint in endpoints:
        if endpoint.scheme == "http" and endpoint.host not in MCP_NON_HTTPS_LOCAL_EXCEPTIONS:
            raw_candidates.append((endpoint.endpoint_key, _non_https_candidate(endpoint)))

        if endpoint.is_ip and endpoint.is_public_ip:
            raw_candidates.append((endpoint.endpoint_key, _raw_ip_candidate(endpoint)))

        if is_denylisted(endpoint.host, config.mcp_denylist_domains):
            raw_candidates.append((endpoint.endpoint_key, _denylist_candidate(endpoint)))

    suppressed = suppress_mcp_remote_candidates(raw_candidates)
    return suppressed, []


def resolve_associated_mcp_json(skill_file: Path, root: Path) -> Path | None:
    """Resolve skill-associated `.mcp.json` by nearest-ancestor lookup."""
    skill_dir = skill_file.resolve().parent
    resolved_root = root.resolve()

    current = skill_dir
    while True:
        candidate = current / MCP_JSON_FILENAME
        if candidate.is_file():
            return candidate
        if current == resolved_root:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent

    fallback = resolved_root / MCP_JSON_FILENAME
    if fallback.is_file():
        return fallback

    return None


def parse_referenced_mcp_endpoints(
    mcp_json_path: Path,
    required_servers: tuple[str, ...],
) -> list[McpRemoteEndpoint]:
    """Parse referenced MCP servers from `.mcp.json` and extract URL endpoints."""
    try:
        raw_text = mcp_json_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"unable to read file ({exc})") from exc

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError("top-level JSON must be an object")

    raw_servers = payload.get("mcpServers")
    if not isinstance(raw_servers, dict):
        raise ValueError("`mcpServers` must be an object")

    lines = raw_text.splitlines()
    endpoints: list[McpRemoteEndpoint] = []

    for server_name in sorted(set(required_servers)):
        server_config = raw_servers.get(server_name)
        if not isinstance(server_config, dict):
            continue

        url_value = server_config.get("url")
        if not isinstance(url_value, str) or not url_value.strip():
            continue

        endpoint_url = url_value.strip()
        parsed_url = urlparse(endpoint_url)
        if not parsed_url.scheme or not parsed_url.hostname:
            continue

        host = parsed_url.hostname.lower().strip()
        scheme = parsed_url.scheme.lower().strip()

        ip_value = _parse_ip(host)
        is_ip = ip_value is not None
        is_public_ip = bool(ip_value and ip_value.is_global)

        line, snippet = _find_server_url_evidence(lines, server_name, endpoint_url)
        endpoints.append(
            McpRemoteEndpoint(
                server_name=server_name,
                endpoint_url=endpoint_url,
                endpoint_key=endpoint_url,
                host=host,
                scheme=scheme,
                is_ip=is_ip,
                is_public_ip=is_public_ip,
                evidence=Evidence(
                    path=str(mcp_json_path),
                    line=line,
                    snippet=snippet,
                ),
            )
        )

    return endpoints


def suppress_mcp_remote_candidates(raw_candidates: list[tuple[str, FindingCandidate]]) -> list[FindingCandidate]:
    """Keep only highest-priority MCP remote rule per endpoint."""
    best_by_endpoint: dict[str, FindingCandidate] = {}

    for endpoint_key, candidate in raw_candidates:
        previous = best_by_endpoint.get(endpoint_key)
        if previous is None:
            best_by_endpoint[endpoint_key] = candidate
            continue

        if _candidate_priority(candidate) > _candidate_priority(previous):
            best_by_endpoint[endpoint_key] = candidate

    return [best_by_endpoint[key] for key in sorted(best_by_endpoint)]


def _extract_required_mcp_servers(parsed: ParsedSkillDocument) -> tuple[str, ...]:
    """Extract normalized `requires.mcp` server names from skill frontmatter."""
    frontmatter = parsed.frontmatter
    if not isinstance(frontmatter, dict):
        return ()

    requires = frontmatter.get("requires")
    if not isinstance(requires, dict):
        return ()

    raw_mcp = requires.get("mcp")
    if isinstance(raw_mcp, str):
        normalized = raw_mcp.strip()
        return (normalized,) if normalized else ()

    if not isinstance(raw_mcp, (list, tuple)):
        return ()

    names = [name.strip() for name in raw_mcp if isinstance(name, str) and name.strip()]
    return tuple(sorted(set(names)))


def _find_server_url_evidence(lines: list[str], server_name: str, endpoint_url: str) -> tuple[int | None, str]:
    """Find best-effort line/snippet evidence for a server URL in `.mcp.json` text."""
    server_token = f'"{server_name}"'

    server_index: int | None = None
    for index, line in enumerate(lines, start=1):
        if server_token in line:
            server_index = index
            break

    if server_index is not None:
        for index in range(server_index, len(lines) + 1):
            line = lines[index - 1]
            if '"url"' in line and endpoint_url in line:
                return index, line.strip()

    for index, line in enumerate(lines, start=1):
        if endpoint_url in line:
            return index, line.strip()

    return None, endpoint_url


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse host text into an IP object when host is a raw IP address."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _candidate_priority(candidate: FindingCandidate) -> int:
    """Return precedence priority for MCP remote finding suppression."""
    return MCP_REMOTE_RULE_PRIORITY.get(candidate.rule_id, 0)


def _non_https_candidate(endpoint: McpRemoteEndpoint) -> FindingCandidate:
    """Build finding candidate for non-HTTPS remote MCP endpoint."""
    return FindingCandidate(
        rule_id=MCP_REMOTE_NON_HTTPS_RULE_ID,
        score=MCP_REMOTE_NON_HTTPS_SCORE,
        confidence="high",
        title="MCP remote endpoint uses HTTP",
        description=(
            f"Referenced MCP server '{endpoint.server_name}' uses non-HTTPS endpoint " f"'{endpoint.endpoint_url}'."
        ),
        evidence=endpoint.evidence,
        recommendation="Use HTTPS for remote MCP endpoints and enforce TLS for transit security.",
    )


def _raw_ip_candidate(endpoint: McpRemoteEndpoint) -> FindingCandidate:
    """Build finding candidate for public raw-IP remote MCP endpoint."""
    return FindingCandidate(
        rule_id=MCP_REMOTE_RAW_IP_RULE_ID,
        score=MCP_REMOTE_RAW_IP_SCORE,
        confidence="high",
        title="MCP remote endpoint uses public raw IP",
        description=(
            f"Referenced MCP server '{endpoint.server_name}' uses public raw IP endpoint " f"'{endpoint.endpoint_url}'."
        ),
        evidence=endpoint.evidence,
        recommendation=("Replace raw IP endpoint with a managed domain and enforce endpoint identity controls."),
    )


def _denylist_candidate(endpoint: McpRemoteEndpoint) -> FindingCandidate:
    """Build finding candidate for denylisted remote MCP endpoint."""
    return FindingCandidate(
        rule_id=MCP_REMOTE_DENYLIST_RULE_ID,
        score=MCP_REMOTE_DENYLIST_SCORE,
        confidence="high",
        title="MCP remote endpoint matches denylist",
        description=(
            f"Referenced MCP server '{endpoint.server_name}' uses denylisted endpoint " f"'{endpoint.endpoint_url}'."
        ),
        evidence=endpoint.evidence,
        recommendation="Remove denylisted endpoint and use approved MCP servers only.",
    )
