"""Tests for MVP detector set coverage."""

import json
from pathlib import Path

from razin.config import RaisinConfig, effective_detector_ids, load_config
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
        """---
name: sample-skill
---
endpoint: https://evil.example.net/v1
endpoint2: https://api.openai.com/v1
""",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = NetUnknownDomainDetector()

    allowlist_config = RaisinConfig(allowlist_domains=("api.openai.com",), denylist_domains=())
    denylist_config = RaisinConfig(allowlist_domains=(), denylist_domains=("evil.example.net",))

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
    config = RaisinConfig(typosquat_baseline=("abd",))

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

    findings = detector.run(skill_name="ipv6", parsed=parsed, config=RaisinConfig())

    assert findings
    assert findings[0].rule_id == "NET_RAW_IP"


def test_mcp_required_detector_finds_frontmatter_requirement(basic_repo_root: Path) -> None:
    risky_file = basic_repo_root / "skills" / "risky_skill" / "SKILL.md"
    parsed = parse_skill_markdown_file(risky_file)
    detector = McpRequiredDetector()

    findings = detector.run(skill_name="risky", parsed=parsed, config=RaisinConfig())

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
        config=RaisinConfig(mcp_allowlist_domains=("rube.app",)),
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
        config=RaisinConfig(mcp_denylist_domains=("blocked.example.com",)),
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
        config=RaisinConfig(mcp_denylist_domains=("*",)),
    )

    assert findings
    assert findings[0].rule_id == "MCP_DENYLIST"


def test_tool_invocation_detector_honors_prefixes(tmp_path: Path) -> None:
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
        config=RaisinConfig(tool_prefixes=("RUBE_", "MCP_")),
    )

    assert findings
    assert any("RUBE_SEARCH" in finding.description for finding in findings)
    assert any("MCP_LIST_TOOLS" in finding.description for finding in findings)
    assert all("SOMETHING_ELSE" not in finding.description for finding in findings)


def test_tool_invocation_detector_detects_service_tokens(tmp_path: Path) -> None:
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
        config=RaisinConfig(tool_prefixes=("RUBE_", "MCP_")),
    )

    assert any("SLACK_SEND_MESSAGE" in finding.description for finding in findings)
    assert any("STRIPE_CREATE_CHARGE" in finding.description for finding in findings)
    assert all("USE_THIS_FORMAT" not in finding.description for finding in findings)


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

    findings = detector.run(skill_name="sample", parsed=parsed, config=RaisinConfig())

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

    findings = detector.run(skill_name="sample", parsed=parsed, config=RaisinConfig())

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
        config=RaisinConfig(allowlist_domains=("rube.app",)),
    )

    # rube.app is allowlisted → EXTERNAL_URLS fires for it as context
    assert findings
    assert any("rube.app" in finding.description for finding in findings)
    # evil.example.net is NOT allowlisted → deferred to NET_UNKNOWN_DOMAIN
    assert all("evil.example.net" not in finding.description for finding in findings)


class TestMcpEndpointUrlNormalization:
    """MCP_ENDPOINT should detect /mcp URL even with markdown punctuation."""

    def test_backtick_mcp_url_detected(self, tmp_path: Path) -> None:
        """Backtick-wrapped URL like `https://rube.app/mcp` should be found."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "Add `https://evil.example.net/mcp` as an MCP server.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = McpEndpointDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert findings
        assert findings[0].rule_id == "MCP_ENDPOINT"
        assert "evil.example.net/mcp" in findings[0].description

    def test_paren_mcp_url_detected(self, tmp_path: Path) -> None:
        """Markdown-link wrapped URL like (https://x.com/mcp) should be found."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "See [MCP](https://evil.example.net/mcp) for details.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = McpEndpointDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert findings
        assert findings[0].rule_id == "MCP_ENDPOINT"


class TestOpaqueBlobPrecision:
    """OPAQUE_BLOB should not fire on prose, only on encoded blobs."""

    def test_prose_with_tool_names_not_flagged(self, tmp_path: Path) -> None:
        """Long prose line with UPPER_SNAKE_CASE tool names is NOT opaque."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n"
            "Use `SENDGRID_ADD_A_SINGLE_RECIPIENT_TO_A_LIST` to add a recipient — "
            "this legacy API requires the `recipient_id` to be Base64-encoded.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = OpaqueBlobDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert not findings

    def test_markdown_table_row_not_flagged(self, tmp_path: Path) -> None:
        """Markdown table rows (long with pipes and backticks) are not opaque."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n"
            "| Create Single Send | `SENDGRID_CREATE_SINGLE_SEND` | "
            "`name`, `email__config__*`, `send_at` | Creates a new single send |\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = OpaqueBlobDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert not findings

    def test_actual_base64_blob_still_flagged(self, tmp_path: Path) -> None:
        """Genuine base64 blob without spaces should still trigger."""
        blob = "QUFB" * 25  # 100 chars of repeating base64
        f = _skill_file(
            tmp_path,
            f"---\nname: test\n---\n{blob}\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = OpaqueBlobDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert findings
        assert findings[0].rule_id == "OPAQUE_BLOB"

    def test_high_entropy_no_spaces_still_flagged(self, tmp_path: Path) -> None:
        """Dense hex-like string without spaces triggers."""
        blob = "a1b2c3d4e5f6" * 10  # 120 chars, high entropy, no spaces
        f = _skill_file(
            tmp_path,
            f"---\nname: test\n---\n{blob}\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = OpaqueBlobDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert findings
        assert findings[0].rule_id == "OPAQUE_BLOB"

    def test_short_value_ignored(self, tmp_path: Path) -> None:
        """Values shorter than OPAQUE_MIN_LENGTH are never flagged."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\nshort value\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = OpaqueBlobDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert not findings


class TestAuthConnectionNegation:
    """AUTH_CONNECTION should not fire when hints are negated."""

    def test_negated_no_api_keys_skipped(self, tmp_path: Path) -> None:
        """'No API keys needed' with no other auth hints should not trigger."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n"
            "No API keys needed — just add the endpoint and it works.\n"
            "No token or secret required.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = AuthConnectionDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert not findings

    def test_affirmative_auth_still_fires(self, tmp_path: Path) -> None:
        """Genuine auth requirements should still trigger."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "Authenticate with API key and complete connection setup.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = AuthConnectionDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert findings
        assert findings[0].rule_id == "AUTH_CONNECTION"

    def test_mixed_negated_and_affirmative(self, tmp_path: Path) -> None:
        """If at least 2 non-negated hints remain, still fires."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n"
            "No API keys needed for basic access.\n"
            "But you must authenticate with OAuth and complete the connection.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = AuthConnectionDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert findings
        assert findings[0].rule_id == "AUTH_CONNECTION"


class TestSecretRefPrecision:
    """SECRET_REF should distinguish secret vs non-secret env vars."""

    def test_api_token_env_ref_flagged(self, tmp_path: Path) -> None:
        """${API_TOKEN} is clearly a secret reference."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\ntoken: ${API_TOKEN}\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = SecretRefDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert findings
        assert any(f.rule_id == "SECRET_REF" for f in findings)

    def test_dollar_add_operator_not_flagged(self, tmp_path: Path) -> None:
        """$add is an API operator, not a secret."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" 'Use "$add": {"login_count": 1} to increment the counter.\n',
        )
        parsed = parse_skill_markdown_file(f)
        detector = SecretRefDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert not findings

    def test_dollar_set_operator_not_flagged(self, tmp_path: Path) -> None:
        """$set and $setOnce are API operators, not secrets."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "$set overwrites existing values; $setOnce only sets if not already set.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = SecretRefDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert not findings

    def test_secret_key_in_frontmatter_not_in_body_fields(self, tmp_path: Path) -> None:
        """Keys in frontmatter are not extracted as body fields after B1 fix."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\napi_key: placeholder\n---\n# Docs\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = SecretRefDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert not findings  # frontmatter keys no longer appear in body-scanned fields

    def test_placeholder_secret_value_not_flagged(self, tmp_path: Path) -> None:
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\npassword: CHANGEME\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = SecretRefDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert not findings

    def test_secret_placeholder_in_code_block_not_flagged(self, tmp_path: Path) -> None:
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n~~~yaml\napiKey: your-api-key\n~~~\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = SecretRefDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert not findings


class TestAuthConnectionStrongHints:
    """AUTH_CONNECTION must require at least one strong (auth-specific) hint."""

    def test_weak_hints_only_does_not_fire(self, tmp_path: Path) -> None:
        """'token' + 'connect' (both weak) should no longer trigger."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n"
            "Check responses for pagination tokens and continue fetching until complete.\n"
            "Rube MCP must be connected.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = AuthConnectionDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert not findings

    def test_strong_plus_weak_fires(self, tmp_path: Path) -> None:
        """'authenticate' (strong) + 'connection' (weak) should fire."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "You must authenticate before using the connection.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = AuthConnectionDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert findings
        assert findings[0].rule_id == "AUTH_CONNECTION"

    def test_two_strong_hints_fires(self, tmp_path: Path) -> None:
        """Two strong hints ('oauth' + 'login') should fire."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "Complete OAuth login to proceed.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = AuthConnectionDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert findings

    def test_evidence_points_to_strong_hint_line(self, tmp_path: Path) -> None:
        """Evidence should reference the line with the strong auth hint."""
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n"
            "Pagination uses token cursors.\n"
            "You must authenticate with OAuth to proceed.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = AuthConnectionDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert findings
        assert "authenticate" in findings[0].evidence.snippet.lower()


class TestDomainLocalSuppression:
    """NET_UNKNOWN_DOMAIN should suppress local/dev hosts under balanced profile."""

    def test_localhost_suppressed_balanced(self, tmp_path: Path) -> None:
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "Test server at http://localhost:3000/api\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = NetUnknownDomainDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig(profile="balanced"))
        assert not findings

    def test_localhost_not_suppressed_strict(self, tmp_path: Path) -> None:
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "Test server at http://localhost:3000/api\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = NetUnknownDomainDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig(profile="strict"))
        assert findings
        assert any("localhost" in f.description for f in findings)

    def test_example_com_suppressed_balanced(self, tmp_path: Path) -> None:
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "See https://www.example.com/api for docs.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = NetUnknownDomainDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig(profile="balanced"))
        assert not findings

    def test_real_domain_not_suppressed(self, tmp_path: Path) -> None:
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "endpoint: https://evil.example.net/v1\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = NetUnknownDomainDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig(profile="balanced"))
        assert findings

    def test_dot_local_tld_suppressed(self, tmp_path: Path) -> None:
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "Dev server at http://myapp.local:8080/api\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = NetUnknownDomainDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig(profile="balanced"))
        assert not findings

    def test_github_suppressed_by_default_allowlist(self, tmp_path: Path) -> None:
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "See https://github.com/example/repo for docs.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = NetUnknownDomainDetector()
        findings = detector.run(skill_name="test", parsed=parsed, config=RaisinConfig())
        assert not findings

    def test_ignore_default_allowlist_reenables_github_signal(self, tmp_path: Path) -> None:
        f = _skill_file(
            tmp_path,
            "---\nname: test\n---\n" "See https://github.com/example/repo for docs.\n",
        )
        parsed = parse_skill_markdown_file(f)
        detector = NetUnknownDomainDetector()
        findings = detector.run(
            skill_name="test",
            parsed=parsed,
            config=RaisinConfig(ignore_default_allowlist=True),
        )
        assert findings
        assert any("github.com" in finding.description for finding in findings)
