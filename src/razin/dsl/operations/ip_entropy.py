"""IP address scanning and entropy checking operations for DSL rules."""

from __future__ import annotations

import re
from typing import Any

from razin.constants.detectors import PROSE_MIN_WORDS
from razin.detectors.common import dedupe_candidates, field_evidence
from razin.dsl.operations.shared import (
    extract_raw_ip_addresses,
    is_non_public_ip,
    looks_like_prose,
    shannon_entropy,
)
from razin.model import FindingCandidate
from razin.types.dsl import EvalContext


def run_ip_address_scan(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Scan fields for raw IPv4/IPv6 addresses."""
    score_public: int = match_config.get("score_public", base_score)
    score_non_public: int = match_config.get("score_non_public", base_score)

    findings: list[FindingCandidate] = []
    for field in ctx.parsed.fields:
        ips = extract_raw_ip_addresses(field.value)
        for ip_addr in ips:
            non_public = is_non_public_ip(ip_addr)
            score = score_non_public if non_public else score_public
            if non_public:
                desc = f"Configuration references a non-public raw IP address ({ip_addr.compressed})."
            else:
                desc = (
                    f"Configuration references a public raw IP address ({ip_addr.compressed}), "
                    "bypassing domain controls."
                )
            findings.append(
                FindingCandidate(
                    rule_id="",
                    score=score,
                    confidence="high",
                    title=metadata["title"],
                    description=desc,
                    evidence=field_evidence(ctx.parsed, field),
                    recommendation=metadata["recommendation"],
                )
            )
            break

    return dedupe_candidates(findings) if do_dedupe else findings


def run_entropy_check(
    ctx: EvalContext,
    match_config: dict[str, Any],
    metadata: dict[str, Any],
    base_score: int,
    do_dedupe: bool,
) -> list[FindingCandidate]:
    """Check field values for length, entropy, and base64 patterns."""
    min_length: int = match_config.get("min_length", 80)
    min_entropy: float = match_config.get("min_entropy", 4.5)
    base64_pattern_str: str | None = match_config.get("base64_pattern")
    skip_prose: bool = match_config.get("skip_prose", False)
    prose_min_words: int = match_config.get("prose_min_words", PROSE_MIN_WORDS)

    base64_re = re.compile(base64_pattern_str) if base64_pattern_str else None
    findings: list[FindingCandidate] = []

    for field in ctx.parsed.fields:
        value = field.value.strip()
        if len(value) < min_length:
            continue
        if skip_prose and looks_like_prose(value, prose_min_words):
            continue

        entropy = shannon_entropy(value)
        looks_base64 = bool(base64_re.match(value)) if base64_re else False

        if looks_base64 or entropy >= min_entropy:
            findings.append(
                FindingCandidate(
                    rule_id="",
                    score=base_score,
                    confidence=metadata["confidence"],
                    title=metadata["title"],
                    description=metadata.get("description", ""),
                    evidence=field_evidence(ctx.parsed, field),
                    recommendation=metadata["recommendation"],
                )
            )

    return dedupe_candidates(findings) if do_dedupe else findings
