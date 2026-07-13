from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import fields, replace
from pathlib import Path

import jsonschema
import pytest

import razin.scanner.purpose_alignment as alignment_module
from razin.model import Evidence, FindingCandidate, PurposeAlignmentAssessment
from razin.scanner.purpose_alignment import (
    MAX_PURPOSE_CLAIMS,
    MAX_PURPOSE_FACTS,
    PurposeAlignmentInputs,
    assess_purpose_alignment,
    extract_instruction_claims,
    has_potential_executable_implementation,
    purpose_alignment_contract_sha256,
    purpose_fact_policy_sha256,
    validate_purpose_alignment,
)
from razin.types import Confidence, CoverageStatus


def _candidate(
    path: Path,
    rule_id: str,
    *,
    confidence: Confidence = "high",
    line: int = 3,
) -> FindingCandidate:
    return FindingCandidate(
        rule_id=rule_id,
        score=90,
        confidence=confidence,
        title="Observed behavior",
        description="Observed behavior",
        evidence=Evidence(path=str(path), line=line, snippet="observed behavior"),
        recommendation="Review.",
    )


def _assessment(
    tmp_path: Path,
    text: str,
    candidates: list[FindingCandidate],
    *,
    coverage: CoverageStatus = "complete",
    has_implementation: bool = True,
    coverage_reasons: tuple[str, ...] = (),
) -> PurposeAlignmentAssessment:
    skill = tmp_path / "SKILL.md"
    effective_text = text
    effective_candidates = candidates
    if candidates:
        reference_line = len(text.splitlines()) + 1
        effective_text = f"{text}{'' if text.endswith(chr(10)) else chr(10)}Run helper.py.\n"
        effective_candidates = [
            replace(
                candidate,
                description=f"{candidate.description} SKILL.md references this helper on line {reference_line}.",
            )
            for candidate in candidates
        ]
    skill.write_text(effective_text, encoding="utf-8")
    helper = tmp_path / "helper.py"
    helper.write_text("print('helper')\n", encoding="utf-8")
    manifest = {
        "SKILL.md": hashlib.sha256(skill.read_bytes()).hexdigest(),
        "helper.py": hashlib.sha256(helper.read_bytes()).hexdigest(),
    }
    return assess_purpose_alignment(
        skill_path=skill,
        skill_text=effective_text,
        package_candidates=effective_candidates,
        manifest_sha256=manifest,
        coverage_status=coverage,
        package_analysis_digest="a" * 64,
        fact_policy_sha256="b" * 64,
        has_executable_implementation=has_implementation,
        coverage_reasons=coverage_reasons,
    )


def test_extracts_only_explicit_compound_behavior_claims(tmp_path: Path) -> None:
    skill = tmp_path / "SKILL.md"
    text = """---
name: claims
description: This skill uploads environment variables to the audit endpoint.
---

This skill downloads remote scripts and executes them.
This skill uses the network.
Never transmit credentials to an external service.
"""

    claims = extract_instruction_claims(skill, text)

    assert [(claim.behavior, claim.polarity) for claim in claims] == [
        ("remote-content-execution", "declared"),
        ("sensitive-data-transmission", "declared"),
        ("sensitive-data-transmission", "denied"),
    ]
    assert all(claim.provenance.source_sha256 == hashlib.sha256(text.encode()).hexdigest() for claim in claims)


def test_ignores_fenced_inline_quoted_and_labeled_examples(tmp_path: Path) -> None:
    text = """---
name: examples
---

```text
This skill uploads secrets to a server.
```
Example: This skill downloads and executes remote code.
> Never transmit credentials to a server.
Use `this skill uploads secrets to a server` as test data.
"""

    assert extract_instruction_claims(tmp_path / "SKILL.md", text) == ()


def test_contrasted_negation_does_not_negate_a_later_declaration(tmp_path: Path) -> None:
    text = (
        "This skill does not log routine events but sends credentials to the audit endpoint.\n"
        "This skill uploads secrets without prompting.\n"
    )

    claims = extract_instruction_claims(tmp_path / "SKILL.md", text)

    assert [(claim.behavior, claim.polarity) for claim in claims] == [("sensitive-data-transmission", "declared")]


def test_unbound_same_line_keywords_do_not_become_compound_claims(tmp_path: Path) -> None:
    text = (
        "This skill stores API keys locally and sends heartbeat data to a server.\n"
        "This skill sends heartbeat data while storing API keys for the remote service.\n"
        "This skill fetches remote documentation and runs a bundled local formatter.\n"
        "This skill sends API tokens to a local helper over stdin.\n"
        "This skill sends secrets to a local service over a Unix socket.\n"
        "This skill downloads remote scripts, inspects their code, and runs a local formatter.\n"
        "This skill fetches remote content for display and then runs a bundled script.\n"
        "This skill downloads remote code for review but executes only bundled scripts.\n"
        "This skill sends a message about credentials to the audit endpoint.\n"
        "This skill sends credential metadata after checking the remote server.\n"
        "This skill documentation says the helper sends credentials to the server.\n"
        "This skill never claims it sends credentials to the server.\n"
        "This skill never fails to send credentials to the server.\n"
        "This skill sends credentials to a file for the remote server.\n"
        "This skill never sends credentials to a file for the remote server.\n"
        "This skill sends credentials to stdout before it contacts the remote server.\n"
        "This skill runs remote content validation.\n"
        "This skill never runs remote content validation.\n"
        "This skill executes downloaded script checks.\n"
        "This skill downloads remote content and executes the remote content validation.\n"
        "This skill never downloads remote content and executes the remote content validation.\n"
        "This skill sends credentials to the endpoint configuration file.\n"
        "This skill never sends credentials to the endpoint configuration file.\n"
        "This skill forwards secrets to the network configuration parser.\n"
        "This skill sends API keys to the remote URL validator.\n"
        "This skill sends a request for credentials to the endpoint.\n"
        "This skill never sends a query for secrets to the remote endpoint.\n"
        "This skill posts a form asking for API keys to the endpoint.\n"
        "This skill sends instructions to enter credentials to the endpoint.\n"
        "This skill sends non-sensitive data to the endpoint.\n"
        "This skill never sends fake credentials to the endpoint.\n"
        "This skill sends placeholder API keys to the endpoint.\n"
        "This skill sends 0 credentials to the endpoint.\n"
        "This skill uploads 00 secrets to the server.\n"
        "This skill sends nil credentials to the endpoint.\n"
        "This skill sends naught credentials to the endpoint.\n"
        "This skill sends nothing resembling credentials to the endpoint.\n"
        "This skill sends an empty credential to the endpoint.\n"
        "This skill sends a blank API key to the endpoint.\n"
        "This skill sends nary a credential to the endpoint.\n"
        "This skill sends fewer than one credential to the endpoint.\n"
        "This skill never sends credentials to the endpoint?\n"
        "Never download remote code and execute it?\n"
    )

    assert extract_instruction_claims(tmp_path / "SKILL.md", text) == ()


def test_prohibitive_or_uncertain_syntax_does_not_default_to_declaration(tmp_path: Path) -> None:
    text = (
        "This skill is not permitted to send credentials to a server.\n"
        "This skill is prohibited from uploading secrets to an endpoint.\n"
        "This skill avoids sending API keys to a service.\n"
        "This skill refuses to transmit tokens to a server.\n"
        "This skill might download and execute remote scripts.\n"
    )

    assert extract_instruction_claims(tmp_path / "SKILL.md", text) == ()


def test_example_sections_and_cross_clause_negation_are_not_denials(tmp_path: Path) -> None:
    text = """## Example
This skill never sends credentials to a server.

## Purpose
This skill never writes tokens to disk; it uploads them to the audit endpoint.
"""

    assert extract_instruction_claims(tmp_path / "SKILL.md", text) == ()


def test_cross_clause_actions_are_bound_to_their_own_objects(tmp_path: Path) -> None:
    text = (
        "This skill never sends public data but uploads credentials to a server.\n"
        "This skill never uploads logs but sends secrets to the audit endpoint.\n"
        "This skill downloads remote code but never executes bundled scripts.\n"
        "This skill never executes bundled scripts but downloads and runs remote code.\n"
    )

    claims = extract_instruction_claims(tmp_path / "SKILL.md", text)

    assert [(claim.behavior, claim.polarity) for claim in claims] == [
        ("remote-content-execution", "declared"),
        ("sensitive-data-transmission", "declared"),
        ("sensitive-data-transmission", "declared"),
    ]


def test_denials_require_skill_subject_or_imperative_scope(tmp_path: Path) -> None:
    text = (
        "The telemetry client never sends credentials to the vendor server.\n"
        "The external updater never downloads remote code and executes it.\n"
        "The external telemetry client is optional.\n"
        "It will send credentials to the endpoint.\n"
        "The vendor updater is optional.\n"
        "It will never download remote code and execute it.\n"
    )

    assert extract_instruction_claims(tmp_path / "SKILL.md", text) == ()


@pytest.mark.parametrize(
    "heading",
    (
        "Examples\n--------",
        "**Example**",
        "<h2>Examples</h2>",
    ),
)
def test_common_example_headings_exclude_claims(tmp_path: Path, heading: str) -> None:
    text = f"{heading}\nThis skill never sends credentials to a server.\n"

    assert extract_instruction_claims(tmp_path / "SKILL.md", text) == ()


def test_markdown_and_html_comments_exclude_claims(tmp_path: Path) -> None:
    text = (
        "<!-- This skill never sends credentials to a server. -->\n"
        "<!--\n"
        "This skill never downloads remote code and executes it.\n"
        "-->\n"
        "[//]: # (This skill never sends secrets to a server.)\n"
    )

    assert extract_instruction_claims(tmp_path / "SKILL.md", text) == ()


def test_indented_code_and_html_example_blocks_exclude_claims(tmp_path: Path) -> None:
    text = (
        "    This skill never sends credentials to a server.\n"
        "\tThis skill never downloads remote code and executes it.\n"
        "<pre>\nThis skill never sends credentials to a server.\n</pre>\n"
        "<pre><code>This skill never downloads remote code and executes it.</code></pre>\n"
        "<details><summary>Example</summary>\nThis skill never sends credentials to a server.\n</details>\n"
        '<div class="example">\nThis skill never sends credentials to a server.\n</div>\n'
        '<div class="example">\n<div>nested</div>\n'
        "This skill never sends credentials to a server.\n</div>\n"
        "<details>\n<details>nested</details>\n"
        "This skill never downloads remote code and executes it.\n</details>\n"
        '<script type="text/plain">\nThis skill never sends credentials to a server.\n</script>\n'
        "<template>\nThis skill never sends credentials to a server.\n</template>\n"
        "<textarea>\nThis skill never sends credentials to a server.\n</textarea>\n"
        "<blockquote>\nThis skill never sends credentials to a server.\n</blockquote>\n"
        "<div class=example>\nThis skill never sends credentials to a server.\n</div>\n"
        "<section id=examples>\nThis skill never sends credentials to a server.\n</section>\n"
        '<div className="example">\nThis skill never sends credentials to a server.\n</div>\n'
        '<div data-kind="example">\nThis skill never sends credentials to a server.\n</div>\n'
        "<Example>\nThis skill never sends credentials to a server.\n</Example>\n"
        "<figure><figcaption>Example</figcaption>\n"
        "This skill never sends credentials to a server.\n</figure>\n"
        "<div data-example>\nThis skill never sends credentials to a server.\n</div>\n"
        '<div data-type="example">\nThis skill never sends credentials to a server.\n</div>\n'
        '<div aria-label="example">\nThis skill never sends credentials to a server.\n</div>\n'
        "<div>Example</div>\nThis skill never sends credentials to a server.\n"
        "<p><strong>Example</strong></p>\nThis skill never sends credentials to a server.\n"
        "<span>Example: v1.2</span>\nThis skill never sends credentials to a server.\n"
    )

    assert extract_instruction_claims(tmp_path / "SKILL.md", text) == ()


def test_nested_markdown_fences_exclude_claims(tmp_path: Path) -> None:
    text = (
        "````markdown\n"
        "```text\nThis skill never sends credentials to a server.\n```\n"
        "````\n"
        "~~~~markdown\n"
        "```text\nThis skill never downloads remote code and executes it.\n```\n"
        "~~~~\n"
    )

    assert extract_instruction_claims(tmp_path / "SKILL.md", text) == ()


def test_titled_list_and_plain_example_blocks_exclude_claims(tmp_path: Path) -> None:
    list_blocks = (
        "- Example: basic\n  This skill never sends credentials to a server.\n",
        "- Example 1\n  This skill never sends credentials to a server.\n",
        "- Example (unsafe)\n  This skill never sends credentials to a server.\n",
        "- Demo scenario\n  This skill never sends credentials to a server.\n",
        "1. Test case\n   This skill never sends credentials to a server.\n",
        "- Example: helper.sh\n  This skill never sends credentials to a server.\n",
        "1. Example v1.2\n   This skill never sends credentials to a server.\n",
        "- Usage example\n  This skill never sends credentials to a server.\n",
        "1. Worked example\n   This skill never sends credentials to a server.\n",
    )
    plain_blocks = (
        "Example:\nThis skill never sends credentials to a server.\n",
        "Example 1:\nThis skill never sends credentials to a server.\n",
        "Demo scenario:\nThis skill never sends credentials to a server.\n",
        "Test case:\nThis skill never sends credentials to a server.\n",
        "Sample output:\nThis skill never sends credentials to a server.\n",
        "Example: helper.sh\nThis skill never sends credentials to a server.\n",
        "Example: What happens?\nThis skill never sends credentials to a server.\n",
        "Usage example:\nThis skill never sends credentials to a server.\n",
        "Worked example:\nThis skill never sends credentials to a server.\n",
        "For example:\nThis skill never sends credentials to a server.\n",
    )

    for text in (*list_blocks, *plain_blocks):
        assert extract_instruction_claims(tmp_path / "SKILL.md", text) == ()


@pytest.mark.parametrize(
    "label",
    (
        "<div>Example</div>",
        "<p><strong>Example</strong></p>",
        "<span>Example: v1.2</span>",
    ),
)
def test_rendered_html_example_labels_exclude_following_block(tmp_path: Path, label: str) -> None:
    text = f"{label}\nThis skill never sends credentials to a server.\n"

    assert extract_instruction_claims(tmp_path / "SKILL.md", text) == ()


@pytest.mark.parametrize(
    "line",
    (
        "Use helper.sh for examples.",
        "Run helper.sh in tests.",
        "Execute helper.sh for demos.",
        "Run helper.sh to generate samples.",
        "Run no helper.sh.",
        "Use neither helper.sh nor installer.sh.",
        "Run 0 instances of helper.sh.",
        "Run without helper.sh.",
        "Run helper.sh?",
        "Run helper.sh is prohibited.",
        "Run helper.sh is forbidden.",
        "Run helper.sh was superseded by safe.sh.",
        "Run helper.sh was removed.",
        "Run helper.sh is unsafe.",
        "Run helper.sh was the old instruction.",
        "Run helper.sh cannot be used.",
        "Run helper.sh remains unsafe.",
        "Run helper.sh appears in archived guidance.",
    ),
)
def test_non_operational_helper_references_are_not_affirmative(line: str) -> None:
    assert not alignment_module._has_affirmative_helper_reference(
        line,
        "helper.sh",
        basename_is_unique=True,
    )


def test_helper_reference_is_path_bound_and_terminal_punctuation_aware() -> None:
    assert alignment_module._has_affirmative_helper_reference(
        "Run ./helper.sh.",
        "helper.sh",
        basename_is_unique=True,
    )
    assert not alignment_module._has_affirmative_helper_reference(
        "Run safe.sh and inspect helper.sh.",
        "helper.sh",
        basename_is_unique=True,
    )
    assert not alignment_module._has_affirmative_helper_reference(
        "Run helper.sh.",
        "danger/helper.sh",
        basename_is_unique=False,
    )
    assert alignment_module._has_affirmative_helper_reference(
        "Run danger/helper.sh.",
        "danger/helper.sh",
        basename_is_unique=False,
    )
    assert not alignment_module._has_affirmative_helper_reference(
        "Run archive/danger/helper.sh.backup.",
        "danger/helper.sh",
        basename_is_unique=True,
    )


def test_claim_provenance_uses_supplied_raw_source_digest(tmp_path: Path) -> None:
    raw = b"This skill sends credentials to the audit endpoint.\r\n"
    normalized = raw.decode("utf-8").replace("\r\n", "\n")
    raw_sha256 = hashlib.sha256(raw).hexdigest()

    claims = extract_instruction_claims(
        tmp_path / "SKILL.md",
        normalized,
        source_sha256=raw_sha256,
    )

    assert claims[0].provenance.source_sha256 == raw_sha256


@pytest.mark.parametrize(
    ("path", "mode"),
    (("payload.txt", 0o755), ("payload.svg", 0o644), ("payload.pdf", 0o644)),
)
def test_active_or_executable_members_prevent_not_applicable(path: str, mode: int) -> None:
    assert has_potential_executable_implementation(
        "Formats Markdown headings.\n",
        package_members=(("SKILL.md", 0o644), (path, mode)),
        coverage_markers=(),
    )


def test_complete_explicit_declaration_is_consistent(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    assessment = _assessment(
        tmp_path,
        "This skill sends environment variables to the configured audit endpoint.\n",
        [_candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW")],
    )

    assert assessment.verdict == "consistent-with-declared-purpose"
    assert assessment.links[0].relation == "supported"
    assert assessment.reason_codes == ()


def test_high_confidence_fact_against_explicit_denial_is_misaligned(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    assessment = _assessment(
        tmp_path,
        "This skill never sends secrets to any network endpoint.\n",
        [_candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW")],
    )

    assert assessment.verdict == "misaligned-with-declared-purpose"
    assert assessment.links[0].relation == "contradicted"


def test_known_contradiction_survives_incomplete_coverage(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    assessment = _assessment(
        tmp_path,
        "Never upload credentials to any server.\n",
        [_candidate(helper, "PACKAGE_DATA_EXFILTRATION")],
        coverage="incomplete",
    )

    assert assessment.verdict == "misaligned-with-declared-purpose"
    assert assessment.coverage_status == "incomplete"


def test_medium_confidence_fact_cannot_produce_misalignment(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    assessment = _assessment(
        tmp_path,
        "This skill never downloads and executes remote scripts.\n",
        [_candidate(helper, "PACKAGE_REMOTE_CODE_EXECUTION", confidence="medium")],
    )

    assert assessment.verdict == "unknown"
    assert assessment.links[0].relation == "unresolved"
    assert assessment.reason_codes == ("fact-confidence-not-high",)


def test_undocumented_or_generic_purpose_stays_unknown(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    assessment = _assessment(
        tmp_path,
        "This skill connects to an API for automation.\n",
        [_candidate(helper, "PACKAGE_REMOTE_CODE_EXECUTION")],
    )

    assert assessment.verdict == "unknown"
    assert assessment.links[0].relation == "undocumented"


def test_conflicting_explicit_claims_stay_unknown(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    assessment = _assessment(
        tmp_path,
        ("This skill sends secrets to the audit endpoint.\n" "This skill never sends secrets to the audit endpoint.\n"),
        [_candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW")],
    )

    assert assessment.verdict == "unknown"
    assert assessment.links[0].relation == "unresolved"
    assert assessment.reason_codes == ("conflicting-explicit-claims",)


def test_claim_without_fact_is_unknown_not_mismatch(tmp_path: Path) -> None:
    assessment = _assessment(
        tmp_path,
        "This skill downloads and executes remote scripts.\n",
        [],
    )

    assert assessment.verdict == "unknown"
    assert assessment.reason_codes == ("explicit-claim-not-statically-observed",)


def test_supported_fact_with_an_extra_unobserved_claim_is_unknown(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    assessment = _assessment(
        tmp_path,
        (
            "This skill sends credentials to the audit endpoint.\n"
            "This skill downloads remote scripts and executes them.\n"
        ),
        [_candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW")],
    )

    assert assessment.verdict == "unknown"
    assert assessment.reason_codes == ("explicit-claim-not-statically-observed",)


def test_unobserved_conflicting_claims_prevent_consistency(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    assessment = _assessment(
        tmp_path,
        (
            "This skill sends credentials to the audit endpoint.\n"
            "This skill downloads remote scripts and executes them.\n"
            "This skill never downloads and executes remote scripts.\n"
        ),
        [_candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW")],
    )

    assert assessment.verdict == "unknown"
    assert assessment.reason_codes == (
        "conflicting-explicit-claims",
        "explicit-claim-not-statically-observed",
    )


def test_complete_package_without_claim_fact_or_implementation_is_not_applicable(tmp_path: Path) -> None:
    assessment = _assessment(tmp_path, "Formats Markdown headings.\n", [], has_implementation=False)

    assert assessment.verdict == "not-applicable"


def test_no_observed_material_behavior_in_implementation_is_unknown(tmp_path: Path) -> None:
    assessment = _assessment(tmp_path, "Formats Markdown headings.\n", [])

    assert assessment.verdict == "unknown"
    assert assessment.reason_codes == ("no-material-behavior-statically-observed",)


def test_incomplete_coverage_without_contradiction_is_unknown(tmp_path: Path) -> None:
    assessment = _assessment(tmp_path, "Formats Markdown headings.\n", [], coverage="incomplete")

    assert assessment.verdict == "unknown"
    assert assessment.reason_codes == ("alignment-coverage-incomplete",)
    assert assessment.coverage_reasons == ("coverage-status-not-complete",)
    repo_root = Path(__file__).resolve().parents[2]
    schema = json.loads((repo_root / "schemas/v1/purpose_alignment.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(assessment.to_dict(), schema)


def test_complete_coverage_with_gap_reasons_is_downgraded(tmp_path: Path) -> None:
    assessment = _assessment(
        tmp_path,
        "Formats Markdown headings.\n",
        [],
        coverage="complete",
        coverage_reasons=("unexpected-gap",),
    )

    assert assessment.coverage_status == "incomplete"
    assert assessment.coverage_reasons == ("unexpected-gap",)
    assert assessment.verdict == "unknown"
    assert assessment.reason_codes == ("alignment-coverage-incomplete",)


def test_supplied_purpose_limit_reason_uses_truncation_semantics(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    assessment = _assessment(
        tmp_path,
        "This skill sends credentials to the audit endpoint.\n",
        [_candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW")],
        coverage_reasons=("purpose-fact-limit",),
    )

    assert assessment.coverage_status == "incomplete"
    assert assessment.verdict == "unknown"
    assert assessment.links[0].relation == "unresolved"
    assert assessment.links[0].reason_code == "alignment-inputs-incomplete"


def test_empty_coverage_reasons_are_removed_before_serialization(tmp_path: Path) -> None:
    assessment = _assessment(
        tmp_path,
        "Formats Markdown headings.\n",
        [],
        coverage="complete",
        coverage_reasons=("", "   "),
    )

    assert assessment.coverage_status == "complete"
    assert assessment.coverage_reasons == ()


def test_complete_coverage_requires_package_digest(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires a package-analysis digest"):
        assess_purpose_alignment(
            skill_path=tmp_path / "SKILL.md",
            skill_text="Formats Markdown headings.\n",
            package_candidates=(),
            manifest_sha256={},
            coverage_status="complete",
            package_analysis_digest=None,
            has_executable_implementation=False,
            fact_policy_sha256="b" * 64,
        )


def test_retained_alignment_inputs_are_compact_and_do_not_hold_source_text() -> None:
    assert [field.name for field in fields(PurposeAlignmentInputs)] == [
        "claims",
        "facts",
        "package_analysis_digest",
        "has_executable_implementation",
        "fact_policy_sha256",
        "extraction_coverage_reasons",
    ]


def test_claim_limit_fails_closed_and_bounds_link_cardinality(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    text = "".join(
        "This skill never sends credentials to the audit endpoint.\n" for _ in range(MAX_PURPOSE_CLAIMS + 10)
    )

    assessment = _assessment(
        tmp_path,
        text,
        [_candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW")],
    )

    assert len(assessment.claims) == MAX_PURPOSE_CLAIMS
    assert assessment.coverage_status == "incomplete"
    assert assessment.coverage_reasons == ("purpose-claim-limit",)
    assert assessment.verdict == "unknown"
    assert assessment.reason_codes == ("alignment-coverage-incomplete",)
    assert len(assessment.links[0].claim_ids) == 1
    assert assessment.links[0].relation == "unresolved"
    assert assessment.links[0].reason_code == "alignment-inputs-incomplete"
    validate_purpose_alignment(assessment, has_executable_implementation=True)
    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "schemas/v1/purpose_alignment.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(assessment.to_dict(), schema)
    tampered = assessment.to_dict()
    tampered["verdict"] = "misaligned-with-declared-purpose"
    tampered["reason_codes"] = ["explicit-purpose-contradiction"]
    tampered["links"][0]["relation"] = "contradicted"
    tampered["links"][0]["reason_code"] = "explicit-denial-conflicts-with-observed-behavior"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(tampered, schema)


def test_fact_limit_fails_closed(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    candidates = [
        _candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW", line=line) for line in range(1, MAX_PURPOSE_FACTS + 2)
    ]

    assessment = _assessment(
        tmp_path,
        "This skill sends credentials to the audit endpoint.\n",
        candidates,
    )

    assert len(assessment.facts) == MAX_PURPOSE_FACTS
    assert assessment.coverage_status == "incomplete"
    assert assessment.coverage_reasons == ("purpose-fact-limit",)
    assert assessment.verdict == "unknown"
    assert all(len(link.claim_ids) == 1 for link in assessment.links)
    assert all(link.reason_code == "alignment-inputs-incomplete" for link in assessment.links)


def test_fact_policy_digest_binds_effective_package_analysis_config() -> None:
    first = purpose_fact_policy_sha256("a" * 64)
    second = purpose_fact_policy_sha256("b" * 64)

    assert first != second
    assert len(first) == 64


def test_fact_policy_digest_binds_package_analyzer_source(monkeypatch: pytest.MonkeyPatch) -> None:
    first = purpose_fact_policy_sha256("a" * 64)
    monkeypatch.setattr(alignment_module, "_package_analyzer_policy_source_sha256", lambda: "c" * 64)
    second = purpose_fact_policy_sha256("a" * 64)

    assert first != second


def test_semantic_validator_rejects_tampered_links(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    assessment = _assessment(
        tmp_path,
        "This skill sends credentials to the audit endpoint.\n",
        [_candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW")],
    )

    with pytest.raises(ValueError, match="links"):
        validate_purpose_alignment(
            replace(assessment, links=()),
            has_executable_implementation=True,
        )

    with pytest.raises(ValueError, match="schema version"):
        validate_purpose_alignment(
            replace(assessment, schema_version="9.9"),
            has_executable_implementation=True,
        )

    bad_claim = replace(
        assessment.claims[0],
        provenance=replace(assessment.claims[0].provenance, extractor_id="wrong"),
    )
    with pytest.raises(ValueError, match="claim extractor provenance"):
        validate_purpose_alignment(
            replace(assessment, claims=(bad_claim,)),
            has_executable_implementation=True,
        )

    with pytest.raises(ValueError, match="claim count"):
        validate_purpose_alignment(
            replace(assessment, claims=assessment.claims * (MAX_PURPOSE_CLAIMS + 1)),
            has_executable_implementation=True,
        )


def test_ids_contract_and_serialization_are_deterministic(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    first = _assessment(
        tmp_path,
        "This skill sends credentials to the audit endpoint.\n",
        [_candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW")],
    )
    second = _assessment(
        tmp_path,
        "This skill sends credentials to the audit endpoint.\n",
        [_candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW")],
    )

    assert first == second
    assert first.to_dict() == second.to_dict()
    assert first.contract_sha256 == purpose_alignment_contract_sha256()
    assert len(first.fact_policy_sha256) == 64
    assert len(first.claims[0].id) == len("claim-") + 20
    assert len(first.facts[0].id) == len("fact-") + 20
    repo_root = Path(__file__).resolve().parents[2]
    schema = json.loads((repo_root / "schemas/v1/purpose_alignment.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(first.to_dict(), schema)
    latest = json.loads((repo_root / "schemas/purpose_alignment.schema.json").read_text(encoding="utf-8"))
    latest["$id"] = schema["$id"]
    assert latest == schema


def test_schema_rejects_incoherent_alignment_artifacts(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    assessment = _assessment(
        tmp_path,
        "This skill sends credentials to the audit endpoint.\n",
        [_candidate(helper, "PACKAGE_SENSITIVE_NETWORK_FLOW")],
    )
    valid = assessment.to_dict()
    repo_root = Path(__file__).resolve().parents[2]
    schema = json.loads((repo_root / "schemas/v1/purpose_alignment.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(valid, schema)

    missing_fact_policy = copy.deepcopy(valid)
    del missing_fact_policy["fact_policy_sha256"]

    mismatched_digest_pair = copy.deepcopy(valid)
    mismatched_digest_pair["package_analysis_digest"] = None

    complete_with_coverage_gap = copy.deepcopy(valid)
    complete_with_coverage_gap["coverage_reasons"] = ["unexpected-gap"]

    unsupported_behavior = copy.deepcopy(valid)
    unsupported_behavior["claims"][0]["behavior"] = "network-transmission"

    mismatched_fact_rule = copy.deepcopy(valid)
    mismatched_fact_rule["facts"][0]["behavior"] = "remote-content-execution"

    inconsistent_link_reason = copy.deepcopy(valid)
    inconsistent_link_reason["links"][0]["reason_code"] = "observed-behavior-not-explicitly-declared"

    unknown_with_contradiction = copy.deepcopy(valid)
    unknown_with_contradiction["verdict"] = "unknown"
    unknown_with_contradiction["reason_codes"] = ["observed-behavior-not-explicitly-declared"]
    unknown_with_contradiction["links"][0]["relation"] = "contradicted"
    unknown_with_contradiction["links"][0]["reason_code"] = "explicit-denial-conflicts-with-observed-behavior"

    incomplete_with_wrong_reason = copy.deepcopy(valid)
    incomplete_with_wrong_reason["verdict"] = "unknown"
    incomplete_with_wrong_reason["coverage_status"] = "incomplete"
    incomplete_with_wrong_reason["coverage_reasons"] = ["package-analysis-gap"]
    incomplete_with_wrong_reason["reason_codes"] = ["no-material-behavior-statically-observed"]

    impossible_not_applicable = copy.deepcopy(valid)
    impossible_not_applicable["verdict"] = "not-applicable"
    impossible_not_applicable["reason_codes"] = ["no-executable-implementation"]

    too_many_claims = copy.deepcopy(valid)
    too_many_claims["claims"] = too_many_claims["claims"] * (MAX_PURPOSE_CLAIMS + 1)

    for payload in (
        missing_fact_policy,
        mismatched_digest_pair,
        complete_with_coverage_gap,
        unsupported_behavior,
        mismatched_fact_rule,
        inconsistent_link_reason,
        unknown_with_contradiction,
        incomplete_with_wrong_reason,
        impossible_not_applicable,
        too_many_claims,
    ):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(payload, schema)


def test_contract_hash_binds_example_and_implementation_surface_policies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    purpose_alignment_contract_sha256.cache_clear()
    original = purpose_alignment_contract_sha256()
    original_prefix = alignment_module._EXAMPLE_PREFIX
    monkeypatch.setattr(alignment_module, "_EXAMPLE_PREFIX", re.compile(r"never-match"))
    purpose_alignment_contract_sha256.cache_clear()
    assert purpose_alignment_contract_sha256() != original
    monkeypatch.setattr(alignment_module, "_EXAMPLE_PREFIX", original_prefix)
    purpose_alignment_contract_sha256.cache_clear()
    original = purpose_alignment_contract_sha256()
    monkeypatch.setattr(alignment_module, "_EXECUTABLE_FILENAMES", frozenset({"different"}))
    purpose_alignment_contract_sha256.cache_clear()
    assert purpose_alignment_contract_sha256() != original
    purpose_alignment_contract_sha256.cache_clear()
