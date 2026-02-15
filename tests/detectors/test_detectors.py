"""Tests for MVP detector set coverage."""

import json
from pathlib import Path

import pytest

from razin.config import RazinConfig, effective_detector_ids, load_config
from razin.detectors import build_detectors
from razin.detectors.docs.rules import (
    AuthConnectionDetector,
    DynamicSchemaDetector,
    ExternalUrlsDetector,
    McpDenylistDetector,
    McpEndpointDetector,
    McpRequiredDetector,
    ToolInvocationDetector,
)
from razin.detectors.rules import (
    NetDocDomainDetector,
    NetRawIpDetector,
    NetUnknownDomainDetector,
    OpaqueBlobDetector,
    SecretRefDetector,
    TyposquatDetector,
)
from razin.parsers import parse_skill_markdown_file
from razin.scanner.discovery import derive_skill_name


def _skill_file(tmp_path: Path, content: str) -> Path:
    """Write a SKILL.md file and return its path."""
    f = tmp_path / "SKILL.md"
    f.write_text(content, encoding="utf-8")
    return f


def test_risky_fixture_triggers_expected_rule_ids(
    fixtures_root: Path,
    basic_repo_root: Path,
) -> None:
    expected_rules_path = fixtures_root / "expected" / "risky_rules.json"
    risky_file = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"

    config = load_config(basic_repo_root)
    detectors = build_detectors(effective_detector_ids(config))
    parsed = parse_skill_markdown_file(risky_file)
    skill_name = derive_skill_name(risky_file, basic_repo_root)

    candidates = []
    for detector in detectors:
        candidates.extend(detector.run(skill_name=skill_name, parsed=parsed, config=config))

    observed = sorted({candidate.rule_id for candidate in candidates})
    expected = sorted(json.loads(expected_rules_path.read_text(encoding="utf-8")))

    assert observed == expected


def test_benign_file_triggers_no_findings(basic_repo_root: Path) -> None:
    benign_file = basic_repo_root / "skills" / "benign_skill" / "SKILL.md"
    config = load_config(basic_repo_root)
    detectors = build_detectors(effective_detector_ids(config))
    parsed = parse_skill_markdown_file(benign_file)
    skill_name = derive_skill_name(benign_file, basic_repo_root)

    candidates = []
    for detector in detectors:
        candidates.extend(detector.run(skill_name=skill_name, parsed=parsed, config=config))

    assert candidates == []


def test_unknown_domain_detector_respects_allowlist_and_denylist(tmp_path: Path) -> None:
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        "---\nname: sample-skill\n---\n" "```\nhttps://evil.attacker.io/v1\nhttps://api.openai.com/v1\n```\n",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = NetUnknownDomainDetector()

    allowlist_config = RazinConfig(allowlist_domains=("api.openai.com",), denylist_domains=())
    denylist_config = RazinConfig(allowlist_domains=(), denylist_domains=("evil.attacker.io",))

    allow_findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=allowlist_config,
    )
    deny_findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=denylist_config,
    )

    assert any(finding.score == 55 for finding in allow_findings)
    assert any(finding.score == 80 for finding in deny_findings)
    assert all("api.openai.com" not in finding.description for finding in allow_findings)


def test_typosquat_ignores_short_names(tmp_path: Path) -> None:
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        """---
name: abc
---
# Title
""",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = TyposquatDetector()
    config = RazinConfig(typosquat_baseline=("abd",))

    findings = detector.run(skill_name="abc", parsed=parsed, config=config)

    assert findings == []


def test_raw_ip_detector_handles_ipv6(tmp_path: Path) -> None:
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        """---
name: ipv6-skill
---
endpoint: http://[2001:db8::1]/hook
""",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = NetRawIpDetector()

    findings = detector.run(skill_name="ipv6", parsed=parsed, config=RazinConfig())

    assert findings
    assert findings[0].rule_id == "NET_RAW_IP"


def test_mcp_required_detector_finds_frontmatter_requirement(basic_repo_root: Path) -> None:
    risky_file = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(risky_file)
    detector = McpRequiredDetector()

    findings = detector.run(skill_name="risky", parsed=parsed, config=RazinConfig())

    assert findings
    assert findings[0].rule_id == "MCP_REQUIRED"


def test_mcp_endpoint_detector_respects_allowlist(tmp_path: Path) -> None:
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        """---
name: endpoint-check
---
Use https://rube.app/mcp and https://evil.example.net/mcp
""",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = McpEndpointDetector()

    findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=RazinConfig(mcp_allowlist_domains=("rube.app",)),
    )

    assert findings
    assert all("rube.app/mcp" not in finding.description for finding in findings)
    assert any("evil.example.net/mcp" in finding.description for finding in findings)


def test_mcp_denylist_detector_finds_blocked_endpoint(tmp_path: Path) -> None:
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        """---
name: denylist-check
---
Endpoint: https://blocked.example.com/mcp
""",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = McpDenylistDetector()

    findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=RazinConfig(mcp_denylist_domains=("blocked.example.com",)),
    )

    assert findings
    assert findings[0].rule_id == "MCP_DENYLIST"


def test_mcp_denylist_detector_wildcard_blocks_all_mcp_endpoints(tmp_path: Path) -> None:
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        """---
name: wildcard-denylist
---
Endpoint: https://any.example.com/mcp
""",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = McpDenylistDetector()

    findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=RazinConfig(mcp_denylist_domains=("*",)),
    )

    assert findings
    assert findings[0].rule_id == "MCP_DENYLIST"


def test_tool_invocation_detector_honors_prefixes(tmp_path: Path) -> None:
    """Consolidated finding includes prefix-matched tokens."""
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        """---
name: tool-check
---
Use RUBE_SEARCH and MCP_LIST_TOOLS and SOMETHING_ELSE.
""",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = ToolInvocationDetector()

    findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=RazinConfig(tool_prefixes=("RUBE_", "MCP_")),
    )

    assert len(findings) == 1
    assert "2 tool invocation tokens" in findings[0].description
    assert "RUBE_SEARCH" in findings[0].evidence.snippet
    assert "MCP_LIST_TOOLS" in findings[0].evidence.snippet
    assert "SOMETHING_ELSE" not in findings[0].evidence.snippet


def test_tool_invocation_detector_detects_service_tokens(tmp_path: Path) -> None:
    """Service tokens are consolidated into a single finding."""
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        """---
name: tool-check
---
Use SLACK_SEND_MESSAGE and STRIPE_CREATE_CHARGE and USE_THIS_FORMAT.
""",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = ToolInvocationDetector()

    findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=RazinConfig(tool_prefixes=("RUBE_", "MCP_")),
    )

    assert len(findings) == 1
    assert "SLACK_SEND_MESSAGE" in findings[0].evidence.snippet
    assert "STRIPE_CREATE_CHARGE" in findings[0].evidence.snippet


def test_dynamic_schema_detector_is_low_confidence(tmp_path: Path) -> None:
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        """---
name: schema-check
---
Before executing any tool, list tools and inspect schema first.
""",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = DynamicSchemaDetector()

    findings = detector.run(skill_name="sample", parsed=parsed, config=RazinConfig())

    assert findings
    assert findings[0].confidence == "low"
    assert findings[0].rule_id == "DYNAMIC_SCHEMA"


def test_auth_connection_detector_needs_multiple_hints(tmp_path: Path) -> None:
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        """---
name: auth-check
---
Authenticate with API key and complete connection setup.
""",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = AuthConnectionDetector()

    findings = detector.run(skill_name="sample", parsed=parsed, config=RazinConfig())

    assert findings
    assert findings[0].rule_id == "AUTH_CONNECTION"


def test_external_urls_detector_respects_allowlist(tmp_path: Path) -> None:
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        """---
name: urls-check
---
See https://rube.app/docs and https://evil.example.net/collect.
""",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = ExternalUrlsDetector()

    # EXTERNAL_URLS now only fires for allowlisted-domain URLs (context signal).
    # Non-allowlisted domains are left to NET_UNKNOWN_DOMAIN (policy signal).
    findings = detector.run(
        skill_name="sample",
        parsed=parsed,
        config=RazinConfig(allowlist_domains=("rube.app",)),
    )

    # rube.app is allowlisted → EXTERNAL_URLS fires for it as context
    assert findings
    assert any("rube.app" in finding.description for finding in findings)
    # evil.example.net is NOT allowlisted → deferred to NET_UNKNOWN_DOMAIN
    assert all("evil.example.net" not in finding.description for finding in findings)


def test_backtick_mcp_url_detected(tmp_path: Path) -> None:
    """Backtick-wrapped URL like `https://rube.app/mcp` should be found."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "Add `https://evil.example.net/mcp` as an MCP server.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = McpEndpointDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "MCP_ENDPOINT"
    assert "evil.example.net/mcp" in findings[0].description


def test_paren_mcp_url_detected(tmp_path: Path) -> None:
    """Markdown-link wrapped URL like (https://x.com/mcp) should be found."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "See [MCP](https://evil.example.net/mcp) for details.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = McpEndpointDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "MCP_ENDPOINT"


def test_prose_with_tool_names_not_flagged(tmp_path: Path) -> None:
    """Long prose line with UPPER_SNAKE_CASE tool names is NOT opaque."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n"
        "Use `SENDGRID_ADD_A_SINGLE_RECIPIENT_TO_A_LIST` to add a recipient — "
        "this legacy API requires the `recipient_id` to be Base64-encoded.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = OpaqueBlobDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_markdown_table_row_not_flagged(tmp_path: Path) -> None:
    """Markdown table rows (long with pipes and backticks) are not opaque."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n"
        "| Create Single Send | `SENDGRID_CREATE_SINGLE_SEND` | "
        "`name`, `email__config__*`, `send_at` | Creates a new single send |\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = OpaqueBlobDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_actual_base64_blob_still_flagged(tmp_path: Path) -> None:
    """Genuine base64 blob without spaces should still trigger."""
    blob = "QUFB" * 25  # 100 chars of repeating base64
    f = _skill_file(
        tmp_path,
        f"---\nname: test\n---\n{blob}\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = OpaqueBlobDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "OPAQUE_BLOB"


def test_high_entropy_no_spaces_still_flagged(tmp_path: Path) -> None:
    """Dense hex-like string without spaces triggers."""
    blob = "a1b2c3d4e5f6" * 10  # 120 chars, high entropy, no spaces
    f = _skill_file(
        tmp_path,
        f"---\nname: test\n---\n{blob}\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = OpaqueBlobDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "OPAQUE_BLOB"


def test_short_value_ignored(tmp_path: Path) -> None:
    """Values shorter than OPAQUE_MIN_LENGTH are never flagged."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\nshort value\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = OpaqueBlobDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_negated_no_api_keys_skipped(tmp_path: Path) -> None:
    """'No API keys needed' with no other auth hints should not trigger."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n"
        "No API keys needed — just add the endpoint and it works.\n"
        "No token or secret required.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_affirmative_auth_still_fires(tmp_path: Path) -> None:
    """Genuine auth requirements should still trigger."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "Authenticate with API key and complete connection setup.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "AUTH_CONNECTION"


def test_mixed_negated_and_affirmative(tmp_path: Path) -> None:
    """If at least 2 non-negated hints remain, still fires."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n"
        "No API keys needed for basic access.\n"
        "But you must authenticate with OAuth and complete the connection.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "AUTH_CONNECTION"


def test_api_token_env_ref_flagged(tmp_path: Path) -> None:
    """${API_TOKEN} is clearly a secret reference."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\ntoken: ${API_TOKEN}\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert any(f.rule_id == "SECRET_REF" for f in findings)


def test_dollar_add_operator_not_flagged(tmp_path: Path) -> None:
    """$add is an API operator, not a secret."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" 'Use "$add": {"login_count": 1} to increment the counter.\n',
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_dollar_set_operator_not_flagged(tmp_path: Path) -> None:
    """$set and $setOnce are API operators, not secrets."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "$set overwrites existing values; $setOnce only sets if not already set.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_secret_key_in_frontmatter_not_in_body_fields(tmp_path: Path) -> None:
    """Keys in frontmatter are not extracted as body fields after B1 fix."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\napi_key: placeholder\n---\n# Docs\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings  # frontmatter keys no longer appear in body-scanned fields


def test_placeholder_secret_value_not_flagged(tmp_path: Path) -> None:
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\npassword: CHANGEME\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_secret_placeholder_in_code_block_not_flagged(tmp_path: Path) -> None:
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n~~~yaml\napiKey: your-api-key\n~~~\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = SecretRefDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_weak_hints_only_does_not_fire(tmp_path: Path) -> None:
    """'token' + 'connect' (both weak) should no longer trigger."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n"
        "Check responses for pagination tokens and continue fetching until complete.\n"
        "Rube MCP must be connected.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_strong_plus_weak_fires(tmp_path: Path) -> None:
    """'authenticate' (strong) + 'connection' (weak) should fire."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "You must authenticate before using the connection.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "AUTH_CONNECTION"


def test_two_strong_hints_fires(tmp_path: Path) -> None:
    """Two strong hints ('oauth' + 'login') should fire."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "Complete OAuth login to proceed.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings


def test_evidence_points_to_strong_hint_line(tmp_path: Path) -> None:
    """Evidence should reference the line with the strong auth hint."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "Pagination uses token cursors.\n" "You must authenticate with OAuth to proceed.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = AuthConnectionDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert "authenticate" in findings[0].evidence.snippet.lower()


@pytest.mark.parametrize(
    "url_line",
    [
        "Test server at http://localhost:3000/api",
        "See https://www.example.com/api for docs.",
        "Dev server at http://myapp.local:8080/api",
    ],
    ids=["localhost", "example.com", "dot-local"],
)
def test_local_dev_host_suppressed_balanced(tmp_path: Path, url_line: str) -> None:
    f = _skill_file(
        tmp_path,
        f"---\nname: test\n---\n{url_line}\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetUnknownDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig(profile="balanced"))
    assert not findings


def test_localhost_not_suppressed_strict(tmp_path: Path) -> None:
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "```\nhttp://localhost:3000/api\n```\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetUnknownDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig(profile="strict"))
    assert findings
    assert any("localhost" in f.description for f in findings)


def test_real_domain_not_suppressed(tmp_path: Path) -> None:
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "```\nhttps://evil.attacker.io/v1\n```\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetUnknownDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig(profile="balanced"))
    assert findings


def test_github_suppressed_by_default_allowlist(tmp_path: Path) -> None:
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "See https://github.com/example/repo for docs.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetUnknownDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_ignore_default_allowlist_reenables_github_signal(tmp_path: Path) -> None:
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "```\nhttps://github.com/example/repo\n```\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetUnknownDomainDetector()
    findings = detector.run(
        skill_name="test",
        parsed=parsed,
        config=RazinConfig(ignore_default_allowlist=True),
    )
    assert findings
    assert any("github.com" in finding.description for finding in findings)


def test_net_unknown_domain_skips_prose_fields(tmp_path: Path) -> None:
    """NET_UNKNOWN_DOMAIN fires only for code-block URLs, not prose."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\nSee https://unknown-site.io/docs for info.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetUnknownDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_net_doc_domain_fires_on_prose_urls(tmp_path: Path) -> None:
    """NET_DOC_DOMAIN fires for non-allowlisted domains in prose text."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\nSee https://unknown-site.io/docs for info.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetDocDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert findings
    assert findings[0].rule_id == "NET_DOC_DOMAIN"
    assert findings[0].score == 15
    assert findings[0].confidence == "low"
    assert "unknown-site.io" in findings[0].description


def test_net_doc_domain_skips_code_block_urls(tmp_path: Path) -> None:
    """NET_DOC_DOMAIN ignores URLs inside code blocks."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n```\nhttps://unknown-site.io/api\n```\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetDocDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_net_doc_domain_skips_allowlisted_domains(tmp_path: Path) -> None:
    """NET_DOC_DOMAIN does not fire for allowlisted domains in prose."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\nSee https://github.com/owner/repo for details.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetDocDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_net_doc_domain_skips_denylisted_domains(tmp_path: Path) -> None:
    """NET_DOC_DOMAIN does not re-report denylisted domains (handled by NET_UNKNOWN_DOMAIN)."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\nVisit https://bad-actor.io/payload for info.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetDocDomainDetector()
    findings = detector.run(
        skill_name="test",
        parsed=parsed,
        config=RazinConfig(denylist_domains=("bad-actor.io",)),
    )
    assert not findings


def test_strict_subdomains_prevents_subdomain_matching(tmp_path: Path) -> None:
    """With strict_subdomains=True, subdomains are NOT auto-allowlisted."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n```\nhttps://docs.github.com/en/get-started\n```\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetUnknownDomainDetector()

    default_findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    strict_findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig(strict_subdomains=True))

    assert not default_findings, "subdomain should be allowlisted by default"
    assert strict_findings, "strict mode should flag subdomain as unknown"


@pytest.mark.parametrize(
    "domain",
    [
        pytest.param("example.com", id="example_com"),
        pytest.param("example.org", id="example_org"),
        pytest.param("example.net", id="example_net"),
        pytest.param("raw.githubusercontent.com", id="raw_githubusercontent"),
        pytest.param("img.shields.io", id="img_shields_io"),
    ],
)
def test_expanded_allowlist_suppresses_domain(tmp_path: Path, domain: str) -> None:
    """Newly added default allowlist domains do not trigger NET_UNKNOWN_DOMAIN."""
    f = _skill_file(
        tmp_path,
        f"---\nname: test\n---\n```\nhttps://{domain}/path\n```\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetUnknownDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings
