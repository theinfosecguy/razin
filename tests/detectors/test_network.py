"""Tests for network detectors: NET_RAW_IP, NET_UNKNOWN_DOMAIN, NET_DOC_DOMAIN."""

from __future__ import annotations

from pathlib import Path

import pytest

from razin.config import RazinConfig
from razin.detectors.rules import NetDocDomainDetector, NetRawIpDetector, NetUnknownDomainDetector
from razin.parsers import parse_skill_markdown_file

from .conftest import _skill_file


def test_unknown_domain_detector_respects_allowlist_and_denylist(tmp_path: Path) -> None:
    """Allowlisted domains are suppressed; denylisted domains score higher."""
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


def test_raw_ip_detector_handles_ipv6(tmp_path: Path) -> None:
    """NET_RAW_IP handles IPv6 addresses in endpoint fields."""
    sample_file = tmp_path / "SKILL.md"
    sample_file.write_text(
        "---\nname: ipv6-skill\n---\n" "endpoint: http://[2001:db8::1]/hook\n",
        encoding="utf-8",
    )
    parsed = parse_skill_markdown_file(sample_file)
    detector = NetRawIpDetector()

    findings = detector.run(skill_name="ipv6", parsed=parsed, config=RazinConfig())

    assert findings
    assert findings[0].rule_id == "NET_RAW_IP"


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
    """Local dev hosts are suppressed in balanced profile."""
    f = _skill_file(
        tmp_path,
        f"---\nname: test\n---\n{url_line}\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetUnknownDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig(profile="balanced"))
    assert not findings


def test_localhost_not_suppressed_strict(tmp_path: Path) -> None:
    """Localhost is not suppressed in strict profile."""
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
    """Real unknown domains are not suppressed in balanced mode."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "```\nhttps://evil.attacker.io/v1\n```\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetUnknownDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig(profile="balanced"))
    assert findings


def test_github_suppressed_by_default_allowlist(tmp_path: Path) -> None:
    """github.com is in the default allowlist and is suppressed."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\n" "See https://github.com/example/repo for docs.\n",
    )
    parsed = parse_skill_markdown_file(f)
    detector = NetUnknownDomainDetector()
    findings = detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    assert not findings


def test_ignore_default_allowlist_reenables_github_signal(tmp_path: Path) -> None:
    """Ignoring default allowlist re-enables github.com signal."""
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
    assert any("'github.com'" in finding.description for finding in findings)


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
    assert "'unknown-site.io'" in findings[0].description


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


def test_net_doc_domain_reports_denylisted_domains(tmp_path: Path) -> None:
    """NET_DOC_DOMAIN reports denylisted prose domains with high severity."""
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
    assert findings
    assert findings[0].score == 80
    assert findings[0].confidence == "high"
    assert "denylisted" in findings[0].description


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


def test_config_line_url_triggers_net_unknown_domain(tmp_path: Path) -> None:
    """Config-like lines with URLs trigger NET_UNKNOWN_DOMAIN, not NET_DOC_DOMAIN."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\nwebhook: https://unknown-risk.tld/hook\n",
    )
    parsed = parse_skill_markdown_file(f)

    unknown_detector = NetUnknownDomainDetector()
    doc_detector = NetDocDomainDetector()

    unknown_findings = unknown_detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    doc_findings = doc_detector.run(skill_name="test", parsed=parsed, config=RazinConfig())

    assert unknown_findings, "config-line URL should trigger NET_UNKNOWN_DOMAIN"
    assert not doc_findings, "config-line URL should not trigger NET_DOC_DOMAIN"
    assert unknown_findings[0].score in (35, 55), "should use standard NET_UNKNOWN_DOMAIN scoring"


def test_prose_url_does_not_trigger_net_unknown_domain(tmp_path: Path) -> None:
    """Plain prose sentence URLs only trigger NET_DOC_DOMAIN, not NET_UNKNOWN_DOMAIN."""
    f = _skill_file(
        tmp_path,
        "---\nname: test\n---\nSee https://unknown-risk.tld/docs for info.\n",
    )
    parsed = parse_skill_markdown_file(f)

    unknown_detector = NetUnknownDomainDetector()
    doc_detector = NetDocDomainDetector()

    unknown_findings = unknown_detector.run(skill_name="test", parsed=parsed, config=RazinConfig())
    doc_findings = doc_detector.run(skill_name="test", parsed=parsed, config=RazinConfig())

    assert not unknown_findings, "prose URL should not trigger NET_UNKNOWN_DOMAIN"
    assert doc_findings, "prose URL should trigger NET_DOC_DOMAIN"
    assert doc_findings[0].score == 15
