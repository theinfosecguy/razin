# Purpose alignment

Razin reports instruction-to-code purpose alignment as a separate assessment.
It does not change evidence verdicts, coverage, review priority, findings, or
classifier features.

Version 1 is intentionally narrow. It compares only two compound behaviors
that bounded whole-package analysis can establish with useful provenance:

- sensitive data transmitted to a network sink;
- remote content passed to process or code execution.

Generic networking, generic command execution, capability declarations, and
missing documentation do not imply either alignment or misalignment.
Claims are accepted only when the skill subject, compound action, data or code
object, destination or coreference, and any denial are tightly bound in the
same clause. Examples, code fences, comments, uncertain language, local-only
transports, and statements about other components are excluded.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `consistent-with-declared-purpose` | Coverage is complete and every observed material fact has one explicit compatible declaration. |
| `misaligned-with-declared-purpose` | A high-confidence observed fact conflicts with an explicit denial of that exact behavior. |
| `unknown` | Documentation is missing, generic, conflicting, or unverified; a fact is below high confidence; or coverage is incomplete. |
| `not-applicable` | Coverage is complete and the package has no executable implementation, claims, or material behavior facts to compare. |

Absence of a claim is never treated as denial. A declared behavior that static
analysis does not observe remains `unknown`, not a mismatch. A known explicit
contradiction remains visible when other coverage is incomplete, but the
assessment never labels the package malicious.

## Output

When `--output-dir` is set, every skill directory receives
`purpose_alignment.json` beside `findings.json` and `summary.json`. The
versioned schema is `schemas/v1/purpose_alignment.schema.json`.

The artifact contains:

- explicit instruction claims and their polarity;
- code behavior facts derived from whole-package flow analysis;
- fact-to-claim comparison links;
- source path, line, snippet, source digest, and extractor provenance;
- the package-analysis coverage digest, the exact alignment-contract digest,
  and a fact-policy digest bound to the effective package-analysis config.

The contract digest binds the shipped evaluator source, grammar, thresholds,
deduplication, and verdict precedence. The separate fact-policy digest changes
when configuration or package-analyzer source that can affect facts or
confidence changes. Only an eligible, affirmative instruction bound to the
exact helper path can upgrade reference-derived material facts to high
confidence; examples, comments, code, questions, negative prose, and ambiguous
basenames cannot.
Extraction is bounded to 64 claims and 128 facts per package. Reaching either
limit marks alignment coverage incomplete and forces `unknown`; links retain
at most one representative declaration and denial per fact.

The same assessment is available on each Python `PackageOutcome`. Aggregate
counts appear in the terminal summary. Rule selection and output filtering do
not change alignment because the assessment uses the full package-analysis
fact surface independently from emitted findings.

## Limits

This is static purpose comparison, not semantic intent inference. It cannot
prove that prose is truthful, that an unobserved runtime path is safe, or that
a documented behavior is legitimate. Unsupported languages, dynamic content,
parse gaps, truncation, and disabled package analysis force `unknown` unless a
separately known high-confidence fact already contradicts an explicit denial.
