"""Conservative instruction-to-code purpose alignment.

Alignment is independent of maliciousness and review priority. V1 compares
only material compound behaviors already established by bounded package
analysis. Missing or ambiguous documentation remains unknown.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from razin.constants.package_analysis import PACKAGE_COVERAGE_DIGEST_VERSION
from razin.model import (
    AlignmentLink,
    CodeBehaviorFact,
    FindingCandidate,
    InstructionClaim,
    PurposeAlignmentAssessment,
    SourceProvenance,
)
from razin.types import (
    AlignmentRelation,
    ClaimPolarity,
    Confidence,
    CoverageStatus,
    PurposeAlignmentVerdict,
    PurposeBehavior,
)

PURPOSE_ALIGNMENT_SCHEMA_VERSION = "1.0"
PURPOSE_ALIGNMENT_EXTRACTOR_VERSION = "1.0"
PURPOSE_FACT_POLICY_VERSION = "1.0"
MAX_PURPOSE_CLAIMS = 64
MAX_PURPOSE_FACTS = 128
PURPOSE_FACT_CANDIDATE_LIMIT = MAX_PURPOSE_FACTS + 1
CLAIM_EXTRACTOR_ID = "razin-explicit-purpose-claims"
FACT_EXTRACTOR_ID = "razin-package-behavior-facts"

FACT_RULE_BEHAVIORS: dict[str, PurposeBehavior] = {
    "PACKAGE_DATA_EXFILTRATION": "sensitive-data-transmission",
    "PACKAGE_REMOTE_CODE_EXECUTION": "remote-content-execution",
    "PACKAGE_SENSITIVE_NETWORK_FLOW": "sensitive-data-transmission",
}

_TRANSMIT_PATTERN = re.compile(
    r"\b(?:send|sends|sending|transmit|transmits|transmitting|upload|uploads|uploading|"
    r"post|posts|posting|forward|forwards|forwarding|share|shares|sharing|exfiltrat\w*)\b",
    re.IGNORECASE,
)
_SENSITIVE_PATTERN = re.compile(
    r"\b(?:credential|credentials|secret|secrets|token|tokens|api[ -]?key|api[ -]?keys|"
    r"environment variable|environment variables|private data|(?<!non-)sensitive data)\b",
    re.IGNORECASE,
)
_EXTERNAL_DESTINATION_PATTERN = re.compile(
    r"\b(?:(?:configured\s+)?(?:audit\s+)?(?:network\s+|remote\s+)?"
    r"(?:cloud|email|endpoint|server|url|webhook)|http|https|internet)\b|"
    r"\bexternal\s+(?:api|domain|host|service)\b",
    re.IGNORECASE,
)
_DESTINATION_END_PATTERN = re.compile(r"^\s*$")
_SENSITIVE_OBJECT_REJECTION_PATTERN = re.compile(
    r"\b(?:about|asking|demo|describing|development|digest|dummy|enter|example|fake|form|hash|"
    r"blank|empty|fewer|identifier|if|instruction|instructions|mentioning|mock|name|nary|naught|"
    r"neither|nil|no|non|none|nothing|"
    r"nonproduction|"
    r"placeholder|prompt|"
    r"public|query|question|redacted|reference|regarding|request|sample|status|synthetic|test|testing|"
    r"whether|zero)\b|\b0+\b",
    re.IGNORECASE,
)
_DESTINATION_GAP_PATTERN = re.compile(
    r"^\s*(?:at|in|into|on|onto|over|through|to|toward|towards|via|with)\s+"
    r"(?:(?:a|an|any|configured|external|remote|the|their|your)\s+)*"
    r"(?:(?:audit|cloud|email|internet|network|remote|web)\s+)*$",
    re.IGNORECASE,
)
_LOCAL_TRANSPORT_PATTERN = re.compile(
    r"\b(?:local|localhost|stdin|unix\s+socket|named\s+pipe|127\.0\.0\.1)\b",
    re.IGNORECASE,
)
_FETCH_PATTERN_TEXT = (
    r"(?:download|downloads|downloaded|downloading|fetch|fetches|fetched|fetching|"
    r"retrieve|retrieves|retrieved|retrieving)"
)
_EXECUTE_PATTERN_TEXT = (
    r"(?:execute|executes|executed|executing|run|runs|running|launch|launches|launched|" r"invoke|invokes|invoked|eval)"
)
_REMOTE_OBJECT_PATTERN_TEXT = r"(?:code|script|scripts|payload|binary|content)"
_REMOTE_OBJECT_END_PATTERN_TEXT = r"(?=\s*(?:$|[,;.!?)]))"
_REMOTE_FETCH_OBJECT_EXECUTE = re.compile(
    rf"\b(?P<fetch>{_FETCH_PATTERN_TEXT})\b\s+(?:the\s+|a\s+|some\s+)?"
    rf"(?P<object>(?:remote\s+)?{_REMOTE_OBJECT_PATTERN_TEXT})\b"
    rf"\s*,?\s*(?:(?:and|then|and\s+then)\s+|before\s+)"
    rf"(?P<execute>{_EXECUTE_PATTERN_TEXT})\b\s+"
    rf"(?P<coreference>it|them|that|the\s+(?:downloaded|fetched|retrieved|remote)\s+"
    rf"{_REMOTE_OBJECT_PATTERN_TEXT})\b{_REMOTE_OBJECT_END_PATTERN_TEXT}",
    re.IGNORECASE,
)
_REMOTE_SHARED_OBJECT_EXECUTE = re.compile(
    rf"\b(?P<fetch>{_FETCH_PATTERN_TEXT})\b\s+(?:and|then|and\s+then)\s+"
    rf"(?P<execute>{_EXECUTE_PATTERN_TEXT})\b\s+(?:the\s+)?"
    rf"(?P<object>(?:remote|downloaded|fetched|retrieved)\s+{_REMOTE_OBJECT_PATTERN_TEXT})\b"
    rf"{_REMOTE_OBJECT_END_PATTERN_TEXT}",
    re.IGNORECASE,
)
_EXECUTE_REMOTE_OBJECT = re.compile(
    rf"\b(?P<execute>{_EXECUTE_PATTERN_TEXT})\b\s+(?:the\s+)?"
    rf"(?P<object>(?:downloaded|fetched|retrieved|remote)\s+{_REMOTE_OBJECT_PATTERN_TEXT})\b"
    rf"{_REMOTE_OBJECT_END_PATTERN_TEXT}",
    re.IGNORECASE,
)
_REMOTE_CLAIM_EXCLUSION_PATTERN = re.compile(
    r"\b(?:bundled|local|only|for\s+review|for\s+display|for\s+inspection|inspect\w*)\b",
    re.IGNORECASE,
)
_DENIAL_PREFIX_PATTERN = re.compile(
    r"\b(?:does not|doesn't|never|will not|won't|must not|shall not)\b",
    re.IGNORECASE,
)
_DENIAL_INTERVENING_PATTERN = re.compile(
    r"^\s*(?:(?:automatically|directly|ever|explicitly|intentionally)\s+){0,2}$",
    re.IGNORECASE,
)
_ANY_NEGATION_PATTERN = re.compile(
    r"\b(?:not|never|won't|cannot|can't|without|unless|prohibit\w*|forbid\w*|avoid\w*|refus\w*|"
    r"disallow\w*|prevent\w*)\b",
    re.IGNORECASE,
)
_UNCERTAIN_PATTERN = re.compile(r"\b(?:can|could|may|might|possibly|optionally)\b", re.IGNORECASE)
_INTERROGATIVE_PATTERN = re.compile(r"\?")
_SKILL_SUBJECT_PATTERN = re.compile(
    r"^\s*(?:[-*+]\s+|\d+[.)]\s+)?(?:(?:purpose|permissions?)\s*:\s*)?" r"(?:this|the)\s+(?:skill|script|helper)\b",
    re.IGNORECASE,
)
_IMPERATIVE_PATTERN = re.compile(
    rf"^\s*(?:[-*+]\s+|\d+[.)]\s+)?(?:(?:purpose|permissions?)\s*:\s*)?"
    rf"(?:(?:does not|doesn't|never|will not|won't|must not|shall not)\s+)?"
    rf"(?:{_FETCH_PATTERN_TEXT}|{_EXECUTE_PATTERN_TEXT}|send(?:s|ing)?|transmit(?:s|ting)?|"
    rf"upload(?:s|ing)?|post(?:s|ing)?|forward(?:s|ing)?|share(?:s|ing)?)\b",
    re.IGNORECASE,
)
_SUBJECT_ACTION_PREFIX_PATTERN = re.compile(
    r"^\s*(?:(?:(?:will|shall|always|also|automatically|directly|explicitly|intentionally|securely)\s+)*|"
    r"(?:is\s+(?:configured|designed|intended)\s+to\s+)|"
    r"(?:(?:does not|doesn't|never|will not|won't|must not|shall not)\s+))$",
    re.IGNORECASE,
)
_FENCE_PATTERN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_FRONTMATTER_CLAIM_KEYS = frozenset({"description", "purpose", "permission", "permissions"})
_EXAMPLE_PREFIX = re.compile(r"^\s*(?:example|demo|test|sample)\s*[:：]", re.IGNORECASE)
_EXAMPLE_HEADING = re.compile(r"\b(?:example|examples|demo|demos|test|tests|sample|samples)\b", re.IGNORECASE)
_EXAMPLE_LIST_LABEL_PATTERN = re.compile(
    r"^(?P<indent>[ \t]*)(?P<marker>(?:[-*+]|\d+[.)])\s+)?[^\n]*"
    r"\b(?:example|examples|demo|demos|test|tests|sample|samples)\b[^\n]*$",
    re.IGNORECASE,
)
_ATX_HEADING_PATTERN = re.compile(r"^\s*(#{1,6})\s+(.+?)\s*$")
_SETEXT_UNDERLINE_PATTERN = re.compile(r"^\s*(=+|-+)\s*$")
_BOLD_HEADING_PATTERN = re.compile(r"^\s*(?:\*\*|__)(.+?)(?:\*\*|__)\s*:?[ \t]*$")
_HTML_HEADING_PATTERN = re.compile(r"^\s*<h([1-6])(?:\s[^>]*)?>(.*?)</h\1>\s*$", re.IGNORECASE)
_MARKDOWN_COMMENT_PATTERN = re.compile(r"^\s*\[(?://|comment)\]:\s*#", re.IGNORECASE)
_INDENTED_CODE_PATTERN = re.compile(r"^(?: {4}|\t)")
_HTML_ALWAYS_EXCLUDED_OPEN_PATTERN = re.compile(
    r"<(blockquote|code|demo[\w:-]*|details|example[\w:-]*|figure|iframe|kbd|math|noscript|pre|q|samp|"
    r"sample[\w:-]*|script|style|svg|template|test[\w:-]*|textarea|xmp)\b",
    re.IGNORECASE,
)
_HTML_EXAMPLE_CONTAINER_OPEN_PATTERN = re.compile(
    r"<(div|section)\b[^>]*\b(?:examples?|demos?|tests?|samples?)\b[^>]*>",
    re.IGNORECASE,
)
_HTML_TAG_TOKEN_PATTERN = re.compile(r"<\s*(/?)\s*([a-zA-Z][\w:-]*)\b[^>]*>")
_HTML_TAG_STRIP_PATTERN = re.compile(r"<[^>]+>")
_HTML_VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source"})
_AFFIRMATIVE_HELPER_REFERENCE_PATTERN = re.compile(
    r"^\s*(?:[-*+]\s+|\d+[.)]\s+)?"
    r"(?:(?:this|the)\s+(?:skill|script|helper)\s+(?:will\s+)?)?"
    r"(?:call(?:s)?|execute(?:s)?|invoke(?:s)?|launch(?:es)?|load(?:s)?|run(?:s)?|start(?:s)?|use(?:s)?)\b",
    re.IGNORECASE,
)
_HELPER_INTERPRETERS = frozenset(
    {"bash", "bun", "deno", "node", "perl", "python", "python2", "python3", "ruby", "sh", "zsh"}
)
_HELPER_FLAG_PATTERN = re.compile(r"-{1,2}[A-Za-z0-9_-]+\Z")
_HELPER_TERMINAL_TAIL_PATTERN = re.compile(r"^\s*[`'\"\])}]*\s*[.!;:]?\s*$")
_NON_AFFIRMATIVE_HELPER_REFERENCE_PATTERN = re.compile(
    r"\b(?:avoid|benchmarks?|ci|comparisons?|demos?|deprecated|development|dev|do not|docs?|"
    r"disabled|disallowed|documentation|don't|examples?|fixtures?|forbidden|historical|illustrations?|"
    r"mocks?|naught|neither|never|nil|no|no longer|none|non-?production|not|obsolete|older|only|outputs?|"
    r"previous|prohibited|removed|retired|samples?|staging|superseded|tests?|used to|without|wrong|zero)\b|"
    r"\b0+\b|\?",
    re.IGNORECASE,
)
_EXECUTION_SURFACE_PATTERN = re.compile(
    r"```|~~~|\b(?:run|execute|launch|invoke|command|script|mcp|tool)\b",
    re.IGNORECASE,
)
_EXECUTABLE_SUFFIXES = (
    ".bash",
    ".cjs",
    ".exe",
    ".js",
    ".jsx",
    ".mjs",
    ".node",
    ".ps1",
    ".py",
    ".rb",
    ".sh",
    ".so",
    ".ts",
    ".tsx",
    ".wasm",
    ".zsh",
)
_EXECUTABLE_FILENAMES = frozenset(
    {
        "dockerfile",
        "gemfile",
        "justfile",
        "makefile",
        "package.json",
        "pom.xml",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "taskfile.yaml",
        "taskfile.yml",
    }
)
# Only formats that cannot themselves carry active code remain inert here.
_NON_IMPLEMENTATION_SUFFIXES = frozenset({".gif", ".jpeg", ".jpg", ".png", ".txt", ".webp"})
_SENSITIVE_CLAUSE_BOUNDARY = re.compile(
    r"[;.!?]+|\s*,\s*|\b(?:and|but|while|whereas|then|however|although)\b",
    re.IGNORECASE,
)
_REMOTE_CLAUSE_BOUNDARY = re.compile(
    r"[;.!?]+|\b(?:but|while|whereas|however|although)\b",
    re.IGNORECASE,
)
_MAX_SENSITIVE_OBJECT_GAP_WORDS = 5
_MAX_SENSITIVE_DESTINATION_GAP_WORDS = 6
_MAX_DENIAL_BINDING_GAP_WORDS = 5
_FACT_CONFIDENCE_RANK: dict[Confidence, int] = {"low": 0, "medium": 1, "high": 2}
_SKILL_HELPER_REFERENCE_PATTERN = re.compile(r"SKILL\.md references this helper on line (\d+)\.")
_VERDICT_PRECEDENCE = (
    "purpose-input-extraction-incomplete",
    "known-high-confidence-contradiction",
    "coverage-incomplete",
    "claim-conflict-or-unobserved-claim",
    "no-facts",
    "all-facts-supported",
    "unresolved-links",
)
_NONCOMPLETE_COVERAGE_FALLBACK_REASON = "coverage-status-not-complete"
_CLAIM_LIMIT_COVERAGE_REASON = "purpose-claim-limit"
_FACT_LIMIT_COVERAGE_REASON = "purpose-fact-limit"


@dataclass(frozen=True)
class PurposeAlignmentInputs:
    """Compact, corpus-safe inputs retained until final coverage is known."""

    claims: tuple[InstructionClaim, ...]
    facts: tuple[CodeBehaviorFact, ...]
    package_analysis_digest: str | None
    has_executable_implementation: bool
    fact_policy_sha256: str
    extraction_coverage_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ClaimMatch:
    behavior: PurposeBehavior
    start: int
    end: int
    clause_start: int
    clause_end: int
    action_starts: tuple[int, ...]


@lru_cache(maxsize=1)
def _policy_source_sha256() -> str:
    """Bind the contract to the complete shipped evaluator source."""
    try:
        source = Path(__file__).read_bytes()
    except OSError as exc:  # pragma: no cover - installed source is always present in supported builds
        raise RuntimeError("Purpose-alignment policy source is unavailable") from exc
    return hashlib.sha256(source).hexdigest()


def purpose_alignment_contract() -> dict[str, object]:
    """Return the versioned machine-readable alignment contract."""
    return {
        "schema_version": PURPOSE_ALIGNMENT_SCHEMA_VERSION,
        "extractor_version": PURPOSE_ALIGNMENT_EXTRACTOR_VERSION,
        "extractor_ids": {"claim": CLAIM_EXTRACTOR_ID, "fact": FACT_EXTRACTOR_ID},
        "policy_source_sha256": _policy_source_sha256(),
        "fact_rule_behaviors": dict(sorted(FACT_RULE_BEHAVIORS.items())),
        "fact_policy_version": PURPOSE_FACT_POLICY_VERSION,
        "package_analysis_digest_version": PACKAGE_COVERAGE_DIGEST_VERSION,
        "claim_patterns": {
            "transmit": _TRANSMIT_PATTERN.pattern,
            "sensitive": _SENSITIVE_PATTERN.pattern,
            "external_destination": _EXTERNAL_DESTINATION_PATTERN.pattern,
            "destination_end": _DESTINATION_END_PATTERN.pattern,
            "sensitive_object_rejection": _SENSITIVE_OBJECT_REJECTION_PATTERN.pattern,
            "destination_gap": _DESTINATION_GAP_PATTERN.pattern,
            "local_transport": _LOCAL_TRANSPORT_PATTERN.pattern,
            "remote_fetch_object_execute": _REMOTE_FETCH_OBJECT_EXECUTE.pattern,
            "remote_shared_object_execute": _REMOTE_SHARED_OBJECT_EXECUTE.pattern,
            "execute_remote_object": _EXECUTE_REMOTE_OBJECT.pattern,
            "remote_object_end": _REMOTE_OBJECT_END_PATTERN_TEXT,
            "remote_exclusions": _REMOTE_CLAIM_EXCLUSION_PATTERN.pattern,
            "denial_prefix": _DENIAL_PREFIX_PATTERN.pattern,
            "denial_intervening": _DENIAL_INTERVENING_PATTERN.pattern,
            "ambiguous_negation": _ANY_NEGATION_PATTERN.pattern,
            "uncertainty": _UNCERTAIN_PATTERN.pattern,
            "interrogative": _INTERROGATIVE_PATTERN.pattern,
            "skill_subject": _SKILL_SUBJECT_PATTERN.pattern,
            "imperative": _IMPERATIVE_PATTERN.pattern,
            "subject_action_prefix": _SUBJECT_ACTION_PREFIX_PATTERN.pattern,
            "sensitive_clause_boundary": _SENSITIVE_CLAUSE_BOUNDARY.pattern,
            "remote_clause_boundary": _REMOTE_CLAUSE_BOUNDARY.pattern,
            "fence": _FENCE_PATTERN.pattern,
            "example_prefix": _EXAMPLE_PREFIX.pattern,
            "example_heading": _EXAMPLE_HEADING.pattern,
            "example_list_label": _EXAMPLE_LIST_LABEL_PATTERN.pattern,
            "atx_heading": _ATX_HEADING_PATTERN.pattern,
            "setext_underline": _SETEXT_UNDERLINE_PATTERN.pattern,
            "bold_heading": _BOLD_HEADING_PATTERN.pattern,
            "html_heading": _HTML_HEADING_PATTERN.pattern,
            "markdown_comment": _MARKDOWN_COMMENT_PATTERN.pattern,
            "indented_code": _INDENTED_CODE_PATTERN.pattern,
            "html_always_excluded": _HTML_ALWAYS_EXCLUDED_OPEN_PATTERN.pattern,
            "html_example_container": _HTML_EXAMPLE_CONTAINER_OPEN_PATTERN.pattern,
            "html_tag_token": _HTML_TAG_TOKEN_PATTERN.pattern,
            "html_tag_strip": _HTML_TAG_STRIP_PATTERN.pattern,
            "html_void_tags": sorted(_HTML_VOID_TAGS),
            "affirmative_helper_reference": _AFFIRMATIVE_HELPER_REFERENCE_PATTERN.pattern,
            "helper_interpreters": sorted(_HELPER_INTERPRETERS),
            "helper_flag": _HELPER_FLAG_PATTERN.pattern,
            "helper_terminal_tail": _HELPER_TERMINAL_TAIL_PATTERN.pattern,
            "non_affirmative_helper_reference": _NON_AFFIRMATIVE_HELPER_REFERENCE_PATTERN.pattern,
            "execution_surface": _EXECUTION_SURFACE_PATTERN.pattern,
        },
        "thresholds": {
            "max_claims": MAX_PURPOSE_CLAIMS,
            "max_facts": MAX_PURPOSE_FACTS,
            "fact_candidate_limit": PURPOSE_FACT_CANDIDATE_LIMIT,
            "sensitive_object_gap_words": _MAX_SENSITIVE_OBJECT_GAP_WORDS,
            "sensitive_destination_gap_words": _MAX_SENSITIVE_DESTINATION_GAP_WORDS,
            "denial_binding_gap_words": _MAX_DENIAL_BINDING_GAP_WORDS,
        },
        "frontmatter_claim_keys": sorted(_FRONTMATTER_CLAIM_KEYS),
        "executable_suffixes": list(_EXECUTABLE_SUFFIXES),
        "executable_filenames": sorted(_EXECUTABLE_FILENAMES),
        "non_implementation_suffixes": sorted(_NON_IMPLEMENTATION_SUFFIXES),
        "fact_dedup": {
            "key": ["behavior", "path", "line"],
            "confidence_rank": dict(_FACT_CONFIDENCE_RANK),
            "tie_break": "lexicographically-greatest-rule-id",
        },
        "fact_confidence_policy": {
            "skill_helper_reference_pattern": _SKILL_HELPER_REFERENCE_PATTERN.pattern,
            "only_affirmative_eligible_helper_references_upgrade_reference_based_facts": True,
        },
        "link_claim_selection": "lexicographically-smallest-claim-id-per-polarity",
        "verdict_precedence": list(_VERDICT_PRECEDENCE),
        "noncomplete_coverage_fallback_reason": _NONCOMPLETE_COVERAGE_FALLBACK_REASON,
        "extraction_limit_coverage_reasons": [_CLAIM_LIMIT_COVERAGE_REASON, _FACT_LIMIT_COVERAGE_REASON],
        "policy": {
            "misaligned": "high-confidence fact contradicts sole explicit behavior denial",
            "consistent": "complete coverage and every fact has an explicit compatible declaration",
            "unknown": "missing, ambiguous, conflicting, medium-confidence, or incomplete evidence",
            "not-applicable": "complete coverage, no claims, no facts, and no executable implementation",
        },
    }


@lru_cache(maxsize=1)
def purpose_alignment_contract_sha256() -> str:
    """Hash the exact extraction and comparison contract."""
    payload = json.dumps(purpose_alignment_contract(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@lru_cache(maxsize=1)
def _package_analyzer_policy_source_sha256() -> str:
    """Hash analyzer implementation and constants that determine purpose facts."""
    paths = (
        Path(__file__).with_name("package_analysis.py"),
        Path(__file__).with_name("orchestrator.py"),
        Path(__file__).parents[1] / "constants" / "package_analysis.py",
        Path(__file__).parents[1] / "config" / "fingerprint.py",
    )
    digest = hashlib.sha256()
    try:
        for path in paths:
            digest.update(path.name.encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    except OSError as exc:  # pragma: no cover - supported builds ship source modules
        raise RuntimeError("Package-analysis policy source is unavailable") from exc
    return digest.hexdigest()


def purpose_fact_policy_sha256(package_analysis_config_sha256: str) -> str:
    """Bind fact confidence and rule mapping to the effective analysis policy."""
    payload = {
        "version": PURPOSE_FACT_POLICY_VERSION,
        "package_analysis_config_sha256": package_analysis_config_sha256,
        "package_analysis_digest_version": PACKAGE_COVERAGE_DIGEST_VERSION,
        "purpose_alignment_contract_sha256": purpose_alignment_contract_sha256(),
        "package_analyzer_policy_source_sha256": _package_analyzer_policy_source_sha256(),
        "fact_rule_behaviors": dict(sorted(FACT_RULE_BEHAVIORS.items())),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def has_potential_executable_implementation(
    skill_text: str,
    *,
    package_members: Iterable[tuple[str, int | None]],
    coverage_markers: Iterable[str],
) -> bool:
    """Fail closed before returning a not-applicable assessment."""
    if _EXECUTION_SURFACE_PATTERN.search(skill_text):
        return True
    for raw_path, mode in package_members:
        candidate = Path(raw_path)
        if candidate.name.lower() == "skill.md":
            continue
        if mode is not None and mode & 0o111:
            return True
        if candidate.name.lower() in _EXECUTABLE_FILENAMES or candidate.suffix.lower() in _EXECUTABLE_SUFFIXES:
            return True
        if candidate.suffix.lower() not in _NON_IMPLEMENTATION_SUFFIXES:
            return True
    return any(marker.startswith("dynamic-analysis:") for marker in coverage_markers)


def _stable_id(prefix: str, payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:20]}"


def _heading_at(lines: list[str], index: int) -> tuple[int, str, int] | None:
    raw_line = lines[index]
    atx = _ATX_HEADING_PATTERN.match(raw_line)
    if atx:
        return len(atx.group(1)), atx.group(2), 1
    html = _HTML_HEADING_PATTERN.match(raw_line)
    if html:
        return int(html.group(1)), re.sub(r"<[^>]+>", "", html.group(2)), 1
    bold = _BOLD_HEADING_PATTERN.match(raw_line)
    if bold:
        return 2, bold.group(1), 1
    if index + 1 < len(lines) and raw_line.strip():
        underline = _SETEXT_UNDERLINE_PATTERN.match(lines[index + 1])
        if underline:
            return (1 if underline.group(1).startswith("=") else 2), raw_line.strip(), 2
    return None


def _excluded_html_block_tag(raw_line: str) -> str | None:
    always_excluded = _HTML_ALWAYS_EXCLUDED_OPEN_PATTERN.search(raw_line)
    if always_excluded:
        return always_excluded.group(1).lower()
    example_container = _HTML_EXAMPLE_CONTAINER_OPEN_PATTERN.search(raw_line)
    if example_container:
        return example_container.group(1).lower()
    return None


def _advance_excluded_html_stack(raw_line: str, stack: list[str]) -> None:
    for token in _HTML_TAG_TOKEN_PATTERN.finditer(raw_line):
        closing, raw_tag = token.groups()
        tag = raw_tag.lower()
        if closing:
            if tag in stack:
                while stack:
                    popped = stack.pop()
                    if popped == tag:
                        break
            continue
        if tag not in _HTML_VOID_TAGS and not token.group(0).rstrip().endswith("/>"):
            stack.append(tag)


def _strip_inline_html_comments(raw_line: str) -> str:
    stripped = raw_line
    while "<!--" in stripped:
        before, _marker, remainder = stripped.partition("<!--")
        _comment, closing, after = remainder.partition("-->")
        if not closing:
            return before
        stripped = before + after
    return stripped


def _instruction_lines(skill_text: str) -> Iterable[tuple[int, str]]:
    """Yield claim-eligible prose while excluding examples, comments, and code."""
    lines = skill_text.splitlines()
    in_frontmatter = bool(lines and lines[0].strip() == "---")
    frontmatter_closed = not in_frontmatter
    fence_marker: tuple[str, int] | None = None
    in_html_comment = False
    excluded_html_stack: list[str] = []
    skipped_heading_level: int | None = None
    skipped_example_list_indent: int | None = None
    index = 0
    while index < len(lines):
        line_number = index + 1
        raw_line = lines[index]
        stripped = raw_line.strip()
        if line_number == 1 and in_frontmatter:
            index += 1
            continue
        if in_frontmatter and not frontmatter_closed:
            if stripped == "---":
                frontmatter_closed = True
                index += 1
                continue
            key, separator, value = raw_line.partition(":")
            if separator and key.strip().lower() in _FRONTMATTER_CLAIM_KEYS and value.strip():
                yield line_number, value.strip().strip("'\"")
            index += 1
            continue

        if in_html_comment:
            if "-->" in raw_line:
                in_html_comment = False
            index += 1
            continue
        if "<!--" in raw_line:
            if "-->" not in raw_line.split("<!--", 1)[1]:
                in_html_comment = True
                index += 1
                continue
            raw_line = _strip_inline_html_comments(raw_line)
            stripped = raw_line.strip()
        if _MARKDOWN_COMMENT_PATTERN.match(raw_line):
            index += 1
            continue

        if excluded_html_stack:
            _advance_excluded_html_stack(raw_line, excluded_html_stack)
            index += 1
            continue
        opened_html_tag = _excluded_html_block_tag(raw_line)
        if opened_html_tag is not None:
            _advance_excluded_html_stack(raw_line, excluded_html_stack)
            index += 1
            continue
        if raw_line.lstrip().startswith("<"):
            html_label = _HTML_TAG_STRIP_PATTERN.sub("", raw_line).strip()
            if html_label and _EXAMPLE_LIST_LABEL_PATTERN.match(html_label):
                skipped_heading_level = 7
                index += 1
                continue
        if _INDENTED_CODE_PATTERN.match(raw_line):
            index += 1
            continue

        fence = _FENCE_PATTERN.match(raw_line)
        if fence_marker is not None:
            if (
                fence is not None
                and fence.group(1)[0] == fence_marker[0]
                and len(fence.group(1)) >= fence_marker[1]
                and not fence.group(2).strip()
            ):
                fence_marker = None
            index += 1
            continue
        if fence is not None:
            fence_marker = (fence.group(1)[0], len(fence.group(1)))
            index += 1
            continue

        if skipped_example_list_indent is not None:
            if not stripped:
                index += 1
                continue
            indentation = len(raw_line) - len(raw_line.lstrip(" \t"))
            if indentation > skipped_example_list_indent:
                index += 1
                continue
            skipped_example_list_indent = None
        example_list_label = _EXAMPLE_LIST_LABEL_PATTERN.match(raw_line)
        if example_list_label:
            if example_list_label.group("marker") is None:
                skipped_heading_level = 7
            else:
                skipped_example_list_indent = len(example_list_label.group("indent"))
            index += 1
            continue

        heading = _heading_at(lines, index)
        if heading:
            level, title, consumed = heading
            if skipped_heading_level is not None and level <= skipped_heading_level:
                skipped_heading_level = None
            if _EXAMPLE_HEADING.search(title):
                skipped_heading_level = level
            index += consumed
            continue

        if (
            skipped_heading_level is not None
            or not stripped
            or stripped.startswith(">")
            or _EXAMPLE_PREFIX.match(stripped)
        ):
            index += 1
            continue
        without_inline_code = re.sub(r"`[^`]*`", "", raw_line).strip()
        if without_inline_code:
            yield line_number, without_inline_code
        index += 1


def _eligible_instruction_source_lines(skill_text: str) -> dict[int, str]:
    raw_lines = skill_text.splitlines()
    return {line_number: raw_lines[line_number - 1] for line_number, _processed_line in _instruction_lines(skill_text)}


def _valid_helper_launch_prefix(prefix: str) -> bool:
    normalized = prefix.strip()
    while normalized.startswith(("`", "'", '"', "(")):
        normalized = normalized[1:].lstrip()
    if not normalized:
        return True
    tokens = normalized.split()
    if tokens and tokens[0].lower() in _HELPER_INTERPRETERS:
        tokens = tokens[1:]
    return all(_HELPER_FLAG_PATTERN.fullmatch(token) is not None for token in tokens)


def _has_affirmative_helper_reference(
    line: str,
    relative_path: str,
    *,
    basename_is_unique: bool,
) -> bool:
    action = _AFFIRMATIVE_HELPER_REFERENCE_PATTERN.match(line)
    if action is None or _NON_AFFIRMATIVE_HELPER_REFERENCE_PATTERN.search(line):
        return False
    names = {relative_path}
    if relative_path == Path(relative_path).name or basename_is_unique:
        names.add(Path(relative_path).name)
    target_pattern = re.compile(
        r"(?<![\w./-])(?:\./)?(?:"
        + "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
        + r")(?=$|[\s,;:!?)}\]'\"\x60]|\.(?=\s|$))"
    )
    target = target_pattern.search(line, action.end())
    if target is None:
        return False
    if not _valid_helper_launch_prefix(line[action.end() : target.start()]):
        return False
    return _HELPER_TERMINAL_TAIL_PATTERN.fullmatch(line[target.end() :]) is not None


def _word_count(value: str) -> int:
    return len(re.findall(r"\b\w+\b", value))


def _clause_spans(line: str, boundary: re.Pattern[str]) -> Iterable[tuple[int, int]]:
    start = 0
    for match in boundary.finditer(line):
        if line[start : match.start()].strip():
            yield start, match.start()
        start = match.end()
    if line[start:].strip():
        yield start, len(line)


def _sensitive_claim_matches(line: str) -> Iterable[_ClaimMatch]:
    for clause_start, clause_end in _clause_spans(line, _SENSITIVE_CLAUSE_BOUNDARY):
        clause = line[clause_start:clause_end]
        if _LOCAL_TRANSPORT_PATTERN.search(clause):
            continue
        for action in _TRANSMIT_PATTERN.finditer(clause):
            sensitive = _SENSITIVE_PATTERN.search(clause, action.end())
            object_gap = clause[action.end() : sensitive.start()] if sensitive is not None else ""
            if (
                sensitive is None
                or _word_count(object_gap) > _MAX_SENSITIVE_OBJECT_GAP_WORDS
                or _SENSITIVE_OBJECT_REJECTION_PATTERN.search(object_gap)
            ):
                continue
            destination = _EXTERNAL_DESTINATION_PATTERN.search(clause, sensitive.end())
            if destination is None:
                continue
            destination_gap = clause[sensitive.end() : destination.start()]
            if _word_count(destination_gap) > _MAX_SENSITIVE_DESTINATION_GAP_WORDS:
                continue
            if _DESTINATION_GAP_PATTERN.fullmatch(destination_gap) is None:
                continue
            if _DESTINATION_END_PATTERN.fullmatch(clause[destination.end() :]) is None:
                continue
            yield _ClaimMatch(
                behavior="sensitive-data-transmission",
                start=clause_start + action.start(),
                end=clause_start + destination.end(),
                clause_start=clause_start,
                clause_end=clause_end,
                action_starts=(clause_start + action.start(),),
            )
            break


def _remote_claim_matches(line: str) -> Iterable[_ClaimMatch]:
    patterns = (_REMOTE_FETCH_OBJECT_EXECUTE, _REMOTE_SHARED_OBJECT_EXECUTE, _EXECUTE_REMOTE_OBJECT)
    for clause_start, clause_end in _clause_spans(line, _REMOTE_CLAUSE_BOUNDARY):
        clause = line[clause_start:clause_end]
        if _REMOTE_CLAIM_EXCLUSION_PATTERN.search(clause):
            continue
        for pattern in patterns:
            match = pattern.search(clause)
            if match is None:
                continue
            action_starts = tuple(
                sorted(
                    clause_start + match.start(name)
                    for name in ("fetch", "execute")
                    if name in match.re.groupindex and match.start(name) >= 0
                )
            )
            yield _ClaimMatch(
                behavior="remote-content-execution",
                start=clause_start + match.start(),
                end=clause_start + match.end(),
                clause_start=clause_start,
                clause_end=clause_end,
                action_starts=action_starts,
            )
            break


def _claim_matches(line: str) -> tuple[_ClaimMatch, ...]:
    matches = [*_sensitive_claim_matches(line), *_remote_claim_matches(line)]
    return tuple(sorted(matches, key=lambda item: (item.start, item.end, item.behavior)))


def _claim_is_skill_scoped(line: str, match: _ClaimMatch) -> bool:
    subject = _SKILL_SUBJECT_PATTERN.match(line)
    if subject is None:
        return _IMPERATIVE_PATTERN.match(line) is not None
    if match.clause_start <= subject.end():
        prefix = line[subject.end() : min(match.action_starts)]
        return _SUBJECT_ACTION_PREFIX_PATTERN.fullmatch(prefix) is not None
    clause = line[match.clause_start : match.clause_end]
    return _IMPERATIVE_PATTERN.match(clause) is not None


def _claim_polarity(line: str, match: _ClaimMatch) -> ClaimPolarity | None:
    clause = line[match.clause_start : match.clause_end]
    bound_denials: list[tuple[int, int]] = []
    for denial in _DENIAL_PREFIX_PATTERN.finditer(clause):
        denial_start = match.clause_start + denial.start()
        denial_end = match.clause_start + denial.end()
        for action_start in match.action_starts:
            if denial_end > action_start:
                continue
            intervening = line[denial_end:action_start]
            if _word_count(intervening) <= _MAX_DENIAL_BINDING_GAP_WORDS and _DENIAL_INTERVENING_PATTERN.fullmatch(
                intervening
            ):
                bound_denials.append((denial_start, denial_end))
                break

    relevant_start = match.clause_start
    relevant_text = line[relevant_start : match.end]
    if _UNCERTAIN_PATTERN.search(relevant_text):
        return None
    for negation in _ANY_NEGATION_PATTERN.finditer(relevant_text):
        absolute_start = relevant_start + negation.start()
        absolute_end = relevant_start + negation.end()
        if not any(start <= absolute_start and absolute_end <= end for start, end in bound_denials):
            return None
    return "denied" if bound_denials else "declared"


def _extract_instruction_claims_bounded(
    skill_path: Path,
    skill_text: str,
    *,
    source_sha256: str | None = None,
) -> tuple[tuple[InstructionClaim, ...], bool]:
    """Extract a bounded claim set and report whether more claims existed."""
    effective_source_sha256 = source_sha256 or hashlib.sha256(skill_text.encode("utf-8")).hexdigest()
    claims: list[InstructionClaim] = []
    for line_number, line in _instruction_lines(skill_text):
        if _INTERROGATIVE_PATTERN.search(line):
            continue
        for match in _claim_matches(line):
            if not _claim_is_skill_scoped(line, match):
                continue
            polarity = _claim_polarity(line, match)
            if polarity is None:
                continue
            if len(claims) >= MAX_PURPOSE_CLAIMS:
                ordered = tuple(
                    sorted(claims, key=lambda item: (item.behavior, item.polarity, item.provenance.line or 0, item.id))
                )
                return ordered, True
            payload = {
                "behavior": match.behavior,
                "polarity": polarity,
                "path": skill_path.name,
                "line": line_number,
                "match_start": match.start,
                "match_end": match.end,
                "source_sha256": effective_source_sha256,
            }
            claims.append(
                InstructionClaim(
                    id=_stable_id("claim", payload),
                    behavior=match.behavior,
                    polarity=polarity,
                    provenance=SourceProvenance(
                        path=skill_path.name,
                        line=line_number,
                        snippet=line[:240],
                        source_sha256=effective_source_sha256,
                        extractor_id=CLAIM_EXTRACTOR_ID,
                        extractor_version=PURPOSE_ALIGNMENT_EXTRACTOR_VERSION,
                    ),
                )
            )
    ordered = tuple(sorted(claims, key=lambda item: (item.behavior, item.polarity, item.provenance.line or 0, item.id)))
    return ordered, False


def extract_instruction_claims(
    skill_path: Path,
    skill_text: str,
    *,
    source_sha256: str | None = None,
) -> tuple[InstructionClaim, ...]:
    """Extract only explicit, tightly bound compound-behavior claims."""
    claims, _truncated = _extract_instruction_claims_bounded(
        skill_path,
        skill_text,
        source_sha256=source_sha256,
    )
    return claims


def _relative_fact_path(package_root: Path, raw_path: str) -> str:
    try:
        return Path(raw_path).resolve().relative_to(package_root.resolve()).as_posix()
    except (OSError, ValueError):
        return Path(raw_path).name


def _fact_location_order(key: tuple[PurposeBehavior, str, int | None]) -> tuple[str, str, int]:
    return key[0], key[1], key[2] or 0


def _extract_code_behavior_facts_bounded(
    package_root: Path,
    candidates: Iterable[FindingCandidate],
    *,
    manifest_sha256: Mapping[str, str | None],
    eligible_instruction_source_lines: Mapping[int, str] | None = None,
) -> tuple[tuple[CodeBehaviorFact, ...], bool]:
    """Map package-analysis chains to a bounded deterministic fact set."""
    facts_by_location: dict[tuple[PurposeBehavior, str, int | None], CodeBehaviorFact] = {}
    basename_counts: dict[str, int] = {}
    for manifest_path in manifest_sha256:
        basename = Path(manifest_path).name
        basename_counts[basename] = basename_counts.get(basename, 0) + 1
    largest_location: tuple[PurposeBehavior, str, int | None] | None = None
    truncated = False
    for candidate in candidates:
        behavior = FACT_RULE_BEHAVIORS.get(candidate.rule_id)
        if behavior is None:
            continue
        relative_path = _relative_fact_path(package_root, candidate.evidence.path)
        confidence = candidate.confidence
        helper_reference = _SKILL_HELPER_REFERENCE_PATTERN.search(candidate.description)
        if (
            candidate.rule_id
            in {
                "PACKAGE_DATA_EXFILTRATION",
                "PACKAGE_REMOTE_CODE_EXECUTION",
                "PACKAGE_SENSITIVE_NETWORK_FLOW",
            }
            and confidence == "high"
            and eligible_instruction_source_lines is not None
            and (
                helper_reference is None
                or not _has_affirmative_helper_reference(
                    eligible_instruction_source_lines.get(int(helper_reference.group(1)), ""),
                    relative_path,
                    basename_is_unique=basename_counts.get(Path(relative_path).name, 0) == 1,
                )
            )
        ):
            confidence = "medium"
        source_sha256 = manifest_sha256.get(relative_path)
        payload = {
            "behavior": behavior,
            "confidence": confidence,
            "rule_id": candidate.rule_id,
            "path": relative_path,
            "line": candidate.evidence.line,
            "source_sha256": source_sha256,
        }
        fact = CodeBehaviorFact(
            id=_stable_id("fact", payload),
            behavior=behavior,
            confidence=confidence,
            rule_id=candidate.rule_id,
            provenance=SourceProvenance(
                path=relative_path,
                line=candidate.evidence.line,
                snippet=candidate.evidence.snippet[:240],
                source_sha256=source_sha256,
                extractor_id=FACT_EXTRACTOR_ID,
                extractor_version=PURPOSE_ALIGNMENT_EXTRACTOR_VERSION,
            ),
        )
        key = (behavior, relative_path, candidate.evidence.line)
        existing = facts_by_location.get(key)
        if existing is not None:
            if (_FACT_CONFIDENCE_RANK[fact.confidence], fact.rule_id) > (
                _FACT_CONFIDENCE_RANK[existing.confidence],
                existing.rule_id,
            ):
                facts_by_location[key] = fact
            continue
        if len(facts_by_location) >= MAX_PURPOSE_FACTS:
            truncated = True
            assert largest_location is not None
            if _fact_location_order(key) >= _fact_location_order(largest_location):
                continue
            facts_by_location.pop(largest_location)
        facts_by_location[key] = fact
        largest_location = max(facts_by_location, key=_fact_location_order)
    ordered = tuple(
        sorted(
            facts_by_location.values(),
            key=lambda item: (item.behavior, item.provenance.path, item.provenance.line or 0, item.id),
        )
    )
    return ordered, truncated


def extract_code_behavior_facts(
    package_root: Path,
    candidates: Iterable[FindingCandidate],
    *,
    manifest_sha256: Mapping[str, str | None],
    eligible_instruction_source_lines: Mapping[int, str] | None = None,
) -> tuple[CodeBehaviorFact, ...]:
    """Map package-analysis chains to bounded, intent-free behavior facts."""
    facts, _truncated = _extract_code_behavior_facts_bounded(
        package_root,
        candidates,
        manifest_sha256=manifest_sha256,
        eligible_instruction_source_lines=eligible_instruction_source_lines,
    )
    return facts


def _links_for(
    claims: tuple[InstructionClaim, ...],
    facts: tuple[CodeBehaviorFact, ...],
    *,
    alignment_inputs_complete: bool = True,
) -> tuple[AlignmentLink, ...]:
    claims_by_behavior: dict[PurposeBehavior, list[InstructionClaim]] = {}
    for claim in claims:
        claims_by_behavior.setdefault(claim.behavior, []).append(claim)

    links: list[AlignmentLink] = []
    for fact in facts:
        matching = claims_by_behavior.get(fact.behavior, [])
        declared = tuple(sorted(claim.id for claim in matching if claim.polarity == "declared")[:1])
        denied = tuple(sorted(claim.id for claim in matching if claim.polarity == "denied")[:1])
        claim_ids = tuple(sorted((*declared, *denied)))
        relation: AlignmentRelation
        if not alignment_inputs_complete:
            relation = "unresolved"
            reason = "alignment-inputs-incomplete"
        elif fact.confidence != "high":
            relation = "unresolved"
            reason = "fact-confidence-not-high"
        elif declared and denied:
            relation = "unresolved"
            reason = "conflicting-explicit-claims"
        elif denied:
            relation = "contradicted"
            reason = "explicit-denial-conflicts-with-observed-behavior"
        elif declared:
            relation = "supported"
            reason = "explicit-declaration-supports-observed-behavior"
        else:
            relation = "undocumented"
            reason = "observed-behavior-not-explicitly-declared"
        links.append(AlignmentLink(fact.id, claim_ids, relation, reason))
    return tuple(sorted(links, key=lambda item: item.fact_id))


def _verdict(
    *,
    claims: tuple[InstructionClaim, ...],
    facts: tuple[CodeBehaviorFact, ...],
    links: tuple[AlignmentLink, ...],
    coverage_status: CoverageStatus,
    has_executable_implementation: bool,
    alignment_inputs_complete: bool = True,
) -> tuple[PurposeAlignmentVerdict, tuple[str, ...]]:
    if not alignment_inputs_complete:
        return "unknown", ("alignment-coverage-incomplete",)
    if any(link.relation == "contradicted" for link in links):
        return "misaligned-with-declared-purpose", ("explicit-purpose-contradiction",)
    if coverage_status != "complete":
        return "unknown", ("alignment-coverage-incomplete",)
    claim_polarities: dict[PurposeBehavior, set[ClaimPolarity]] = {}
    for claim in claims:
        claim_polarities.setdefault(claim.behavior, set()).add(claim.polarity)
    conflicting_claims = any(len(polarities) > 1 for polarities in claim_polarities.values())
    observed_behaviors = {fact.behavior for fact in facts}
    unmatched_claims = any(claim.behavior not in observed_behaviors for claim in claims)
    claim_reasons: set[str] = set()
    if conflicting_claims:
        claim_reasons.add("conflicting-explicit-claims")
    if unmatched_claims:
        claim_reasons.add("explicit-claim-not-statically-observed")
    if claim_reasons:
        return "unknown", tuple(sorted(claim_reasons))
    if not facts:
        if has_executable_implementation:
            return "unknown", ("no-material-behavior-statically-observed",)
        return "not-applicable", ("no-executable-implementation",)
    if all(link.relation == "supported" for link in links):
        return "consistent-with-declared-purpose", ()
    return "unknown", tuple(sorted({link.reason_code for link in links if link.relation != "supported"}))


def collect_purpose_alignment_inputs(
    *,
    skill_path: Path,
    skill_text: str,
    skill_source_sha256: str | None,
    package_candidates: Iterable[FindingCandidate],
    manifest_sha256: Mapping[str, str | None],
    package_analysis_digest: str | None,
    has_executable_implementation: bool,
    fact_policy_sha256: str,
    fact_surface_truncated: bool = False,
) -> PurposeAlignmentInputs:
    """Extract compact claims and facts while package inputs are in scope."""
    claims, claims_truncated = _extract_instruction_claims_bounded(
        skill_path,
        skill_text,
        source_sha256=skill_source_sha256,
    )
    facts, facts_truncated = _extract_code_behavior_facts_bounded(
        skill_path.parent,
        package_candidates,
        manifest_sha256=manifest_sha256,
        eligible_instruction_source_lines=_eligible_instruction_source_lines(skill_text),
    )
    extraction_coverage_reasons: list[str] = []
    if claims_truncated:
        extraction_coverage_reasons.append(_CLAIM_LIMIT_COVERAGE_REASON)
    if facts_truncated or fact_surface_truncated:
        extraction_coverage_reasons.append(_FACT_LIMIT_COVERAGE_REASON)
    return PurposeAlignmentInputs(
        claims=claims,
        facts=facts,
        package_analysis_digest=package_analysis_digest,
        has_executable_implementation=has_executable_implementation,
        fact_policy_sha256=fact_policy_sha256,
        extraction_coverage_reasons=tuple(extraction_coverage_reasons),
    )


def _validate_source_provenance(provenance: SourceProvenance) -> None:
    if not isinstance(provenance.path, str) or not provenance.path:
        raise ValueError("purpose alignment source path is invalid")
    if provenance.line is not None and (type(provenance.line) is not int or provenance.line < 1):
        raise ValueError("purpose alignment source line is invalid")
    if not isinstance(provenance.snippet, str) or len(provenance.snippet) > 240:
        raise ValueError("purpose alignment source snippet is invalid")
    if provenance.source_sha256 is not None and re.fullmatch(r"[0-9a-f]{64}", provenance.source_sha256) is None:
        raise ValueError("purpose alignment source digest is invalid")


def validate_purpose_alignment(
    assessment: PurposeAlignmentAssessment,
    *,
    has_executable_implementation: bool,
) -> None:
    """Reject internally inconsistent producer output before serialization."""
    if assessment.schema_version != PURPOSE_ALIGNMENT_SCHEMA_VERSION:
        raise ValueError("purpose alignment schema version is unsupported")
    if assessment.coverage_status not in {"complete", "incomplete", "not-evaluated"}:
        raise ValueError("purpose alignment coverage status is invalid")
    if assessment.verdict not in {
        "consistent-with-declared-purpose",
        "misaligned-with-declared-purpose",
        "unknown",
        "not-applicable",
    }:
        raise ValueError("purpose alignment verdict is invalid")
    alignment_inputs_complete = not {
        _CLAIM_LIMIT_COVERAGE_REASON,
        _FACT_LIMIT_COVERAGE_REASON,
    }.intersection(assessment.coverage_reasons)
    if assessment.contract_sha256 != purpose_alignment_contract_sha256():
        raise ValueError("purpose alignment contract digest does not match the active evaluator")
    if re.fullmatch(r"[0-9a-f]{64}", assessment.fact_policy_sha256) is None:
        raise ValueError("purpose alignment fact-policy digest is invalid")
    digest_present = assessment.package_analysis_digest is not None
    if digest_present != (assessment.package_analysis_digest_version is not None):
        raise ValueError("package-analysis digest and version must be present together")
    if digest_present:
        if re.fullmatch(r"[0-9a-f]{64}", assessment.package_analysis_digest or "") is None:
            raise ValueError("package-analysis digest is invalid")
        if assessment.package_analysis_digest_version != PACKAGE_COVERAGE_DIGEST_VERSION:
            raise ValueError("package-analysis digest version does not match the active analyzer")
    if assessment.coverage_status != "complete" and not assessment.coverage_reasons:
        raise ValueError("non-complete alignment coverage requires a reason")
    if assessment.coverage_status == "complete" and assessment.coverage_reasons:
        raise ValueError("complete alignment coverage cannot carry gap reasons")
    if assessment.coverage_status == "complete" and not digest_present:
        raise ValueError("complete alignment coverage requires a package-analysis digest")
    if any(not reason.strip() for reason in assessment.coverage_reasons):
        raise ValueError("alignment coverage reasons cannot be empty")
    if assessment.coverage_reasons != tuple(sorted(set(assessment.coverage_reasons))):
        raise ValueError("coverage reasons must be sorted and unique")
    if assessment.reason_codes != tuple(sorted(set(assessment.reason_codes))):
        raise ValueError("alignment reason codes must be sorted and unique")
    claim_ids = [claim.id for claim in assessment.claims]
    fact_ids = [fact.id for fact in assessment.facts]
    valid_behaviors = set(FACT_RULE_BEHAVIORS.values())
    for claim in assessment.claims:
        if re.fullmatch(r"claim-[0-9a-f]{20}", claim.id) is None:
            raise ValueError("purpose alignment claim ID is invalid")
        if claim.behavior not in valid_behaviors or claim.polarity not in {"declared", "denied"}:
            raise ValueError("purpose alignment claim value is invalid")
        provenance = claim.provenance
        if (
            provenance.extractor_id != CLAIM_EXTRACTOR_ID
            or provenance.extractor_version != PURPOSE_ALIGNMENT_EXTRACTOR_VERSION
        ):
            raise ValueError("purpose alignment claim extractor provenance is invalid")
        _validate_source_provenance(provenance)
    for fact in assessment.facts:
        if re.fullmatch(r"fact-[0-9a-f]{20}", fact.id) is None:
            raise ValueError("purpose alignment fact ID is invalid")
        if FACT_RULE_BEHAVIORS.get(fact.rule_id) != fact.behavior or fact.confidence not in _FACT_CONFIDENCE_RANK:
            raise ValueError("purpose alignment fact value is invalid")
        provenance = fact.provenance
        if (
            provenance.extractor_id != FACT_EXTRACTOR_ID
            or provenance.extractor_version != PURPOSE_ALIGNMENT_EXTRACTOR_VERSION
        ):
            raise ValueError("purpose alignment fact extractor provenance is invalid")
        _validate_source_provenance(provenance)
    if len(assessment.claims) > MAX_PURPOSE_CLAIMS:
        raise ValueError("purpose alignment claim count exceeds the contract limit")
    if len(assessment.facts) > MAX_PURPOSE_FACTS or len(assessment.links) > MAX_PURPOSE_FACTS:
        raise ValueError("purpose alignment fact or link count exceeds the contract limit")
    if any(len(link.claim_ids) > 2 for link in assessment.links):
        raise ValueError("purpose alignment link claim references exceed the contract limit")
    if len(claim_ids) != len(set(claim_ids)) or len(fact_ids) != len(set(fact_ids)):
        raise ValueError("purpose alignment claim and fact IDs must be unique")
    expected_links = _links_for(
        assessment.claims,
        assessment.facts,
        alignment_inputs_complete=alignment_inputs_complete,
    )
    if assessment.links != expected_links:
        raise ValueError("purpose alignment links are not the deterministic comparison of claims and facts")
    expected_verdict, expected_reasons = _verdict(
        claims=assessment.claims,
        facts=assessment.facts,
        links=assessment.links,
        coverage_status=assessment.coverage_status,
        has_executable_implementation=has_executable_implementation,
        alignment_inputs_complete=alignment_inputs_complete,
    )
    if (assessment.verdict, assessment.reason_codes) != (expected_verdict, expected_reasons):
        raise ValueError("purpose alignment verdict is inconsistent with its evidence")


def finalize_purpose_alignment(
    inputs: PurposeAlignmentInputs,
    *,
    coverage_status: CoverageStatus,
    coverage_reasons: Iterable[str] = (),
) -> PurposeAlignmentAssessment:
    """Finalize an assessment after all structural coverage signals are known."""
    claims = inputs.claims[:MAX_PURPOSE_CLAIMS]
    facts = inputs.facts[:MAX_PURPOSE_FACTS]
    extraction_coverage_reasons = set(inputs.extraction_coverage_reasons)
    supplied_coverage_reasons = {reason for reason in coverage_reasons if reason.strip()}
    extraction_coverage_reasons.update(
        {_CLAIM_LIMIT_COVERAGE_REASON, _FACT_LIMIT_COVERAGE_REASON}.intersection(supplied_coverage_reasons)
    )
    if len(inputs.claims) > MAX_PURPOSE_CLAIMS:
        extraction_coverage_reasons.add(_CLAIM_LIMIT_COVERAGE_REASON)
    if len(inputs.facts) > MAX_PURPOSE_FACTS:
        extraction_coverage_reasons.add(_FACT_LIMIT_COVERAGE_REASON)
    alignment_inputs_complete = not extraction_coverage_reasons
    links = _links_for(
        claims,
        facts,
        alignment_inputs_complete=alignment_inputs_complete,
    )
    effective_coverage_status: CoverageStatus = (
        "incomplete"
        if not alignment_inputs_complete or (coverage_status == "complete" and supplied_coverage_reasons)
        else coverage_status
    )
    verdict, reason_codes = _verdict(
        claims=claims,
        facts=facts,
        links=links,
        coverage_status=effective_coverage_status,
        has_executable_implementation=inputs.has_executable_implementation,
        alignment_inputs_complete=alignment_inputs_complete,
    )
    normalized_coverage_reasons = tuple(sorted({*supplied_coverage_reasons, *extraction_coverage_reasons}))
    if effective_coverage_status != "complete" and not normalized_coverage_reasons:
        normalized_coverage_reasons = (_NONCOMPLETE_COVERAGE_FALLBACK_REASON,)
    assessment = PurposeAlignmentAssessment(
        schema_version=PURPOSE_ALIGNMENT_SCHEMA_VERSION,
        contract_sha256=purpose_alignment_contract_sha256(),
        fact_policy_sha256=inputs.fact_policy_sha256,
        verdict=verdict,
        coverage_status=effective_coverage_status,
        coverage_reasons=normalized_coverage_reasons,
        reason_codes=reason_codes,
        package_analysis_digest=inputs.package_analysis_digest,
        package_analysis_digest_version=(
            PACKAGE_COVERAGE_DIGEST_VERSION if inputs.package_analysis_digest is not None else None
        ),
        claims=claims,
        facts=facts,
        links=links,
    )
    validate_purpose_alignment(
        assessment,
        has_executable_implementation=inputs.has_executable_implementation,
    )
    return assessment


def assess_purpose_alignment(
    *,
    skill_path: Path,
    skill_text: str,
    package_candidates: Iterable[FindingCandidate],
    manifest_sha256: Mapping[str, str | None],
    coverage_status: CoverageStatus,
    package_analysis_digest: str | None,
    has_executable_implementation: bool,
    fact_policy_sha256: str,
    skill_source_sha256: str | None = None,
    coverage_reasons: Iterable[str] = (),
) -> PurposeAlignmentAssessment:
    """Build a deterministic, non-classifying alignment assessment."""
    inputs = collect_purpose_alignment_inputs(
        skill_path=skill_path,
        skill_text=skill_text,
        skill_source_sha256=skill_source_sha256,
        package_candidates=package_candidates,
        manifest_sha256=manifest_sha256,
        package_analysis_digest=package_analysis_digest,
        has_executable_implementation=has_executable_implementation,
        fact_policy_sha256=fact_policy_sha256,
    )
    return finalize_purpose_alignment(
        inputs,
        coverage_status=coverage_status,
        coverage_reasons=coverage_reasons,
    )
