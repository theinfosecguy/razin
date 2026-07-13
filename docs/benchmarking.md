# Benchmarking

Razin's benchmark measures two distinct package-level outcomes:

- **block** is positive only for `high-confidence-malicious-evidence`.
- **review** is positive for either a high-confidence chain or
  `review-required`.

Evidence verdict and structural coverage are independent. An `incomplete` or
`not-evaluated` package earns neither outcome and is penalized in both confusion
matrices even if its evidence verdict is reviewable or high-confidence. Reports include support,
TP/FP/FN/TN, precision, recall, F1, specificity, false-positive rate,
incomplete rate, exact rule matches, and manifest, gate, trusted-config, and
corpus-content hashes.

Reports distinguish `gate_status: not-evaluated` from `passed` and `failed`.
When no gate file is supplied, `gate_passed` is `null`; an ungated evaluation
is never presented as a successful quality gate.

Benchmark manifests remain schema `2.0`; gate configurations and generated
reports use schema `3.0`. Report samples preserve raw evidence predicates but
qualify `block_positive` and `review_positive` on complete structural coverage.

## Synthetic pull-request gate

The checked-in inert corpus contains explicit exfiltration and remote-code
execution chains, a prompt-injection review case, clean controls, and a benign
OAuth near miss. Each semantic fixture declares its expected rule IDs and
block/review outcomes, so an unrelated detector cannot accidentally make CI
green.

```bash
uv run python scripts/evaluate_corpus.py \
  --manifest benchmarks/synthetic/manifest.json \
  --gates benchmarks/gates/synthetic.json \
  --output benchmark-results/synthetic.json \
  --features-output benchmark-results/synthetic-features.json
```

This is a regression gate, not evidence of real-world detector quality.

## Detector feature export

`--features-output` writes a deterministic, research-only artifact. The
extractor sees findings only: labels, sample IDs, paths, evidence text,
coverage, grouping metadata, and package digests cannot influence feature
selection. Each sample is structurally separated into `features`, `target`,
`metadata`, and `audit` objects. A baseline may read only
`features.present_rule_ids` as model input.

Analysis-gap rules, inventory metadata, unknown rules, and `TYPOSQUAT` are
ineligible. `TYPOSQUAT` is excluded because its automatic workspace baseline
can observe held-out package names. Rules driven by operator-configured
indicators, denylists, allowlists, service keywords, tool prefixes, or known-bad
domains are also excluded because a corpus-tuned configuration could encode
labels. The artifact records counts and maximum weights under `audit`, while a
canonical contract hash binds the complete rule-to-eligibility mapping. Stored
1.0 artifacts remain verifiable against the immutable
`schemas/v1/detector_features.schema.json` schema; the root schema tracks the
latest version.

Diagnostic family and filename-derived groups remain metadata. The export
marks campaign and lineage grouping as unavailable, so they cannot be mistaken
for authoritative holdout keys. An authoritative grouped evaluation requires a
separate, trusted grouping sidecar. Provenance records the corpus, manifest,
gates, trusted configuration, scanner source, engine, rulepack, scan
fingerprint, evaluator source, feature schema, profile, effective file-size
limit, and executed/disabled rule surface.

## Grouped interpretable baseline

The reference baseline is a standard-library Bernoulli Naive Bayes model over
eligible binary rule presence. It uses alpha 1 smoothing, empirical class
priors, a fixed three-fold contract, a zero log-odds threshold, and benign
tie-breaking. Each fold learns its vocabulary and parameters from its training
groups only.

```bash
uv run python scripts/evaluate_baseline.py \
  --features benchmark-results/synthetic-features.json \
  --groups benchmarks/synthetic/groups.json \
  --config benchmarks/baselines/bernoulli-nb-v1.json \
  --output benchmark-results/synthetic-baseline.json
```

The grouping sidecar must be explicitly authoritative, bind the exact feature
artifact manifest digest, and cover every sample.
Campaign and lineage relationships plus singleton independent samples are
collapsed into connected components before deterministic label-balanced fold assignment, so no related
component can cross train and test. Missing authoritative grouping produces a
`not-evaluated` report, not a random or filename-derived split. The pinned
MalSkillBench workflow intentionally records that state because its released
corpus does not provide an authoritative campaign/lineage mapping.

Samples with incomplete or unevaluated static coverage abstain. They remain in
the denominator and are conservatively counted as the opposite-class error, so
coverage gaps cannot improve the reference score. Reports include the complete
confusion matrix, precision, recall, specificity, false-positive rate,
balanced accuracy, Matthews correlation coefficient, fold ranges, majority
comparison, and per-feature log-odds contributions. This remains a research
diagnostic, not a deployable malicious-skill classifier.

## Manifest format

```json
{
  "schema_version": "2.0",
  "name": "example-corpus",
  "corpus_root": "/absolute/path/to/corpus",
  "allow_unlisted_skills": false,
  "scanner": {"profile": "balanced", "max_file_mb": 64},
  "samples": [
    {
      "id": "malicious/example",
      "path": "malicious/example/SKILL.md",
      "label": "malicious",
      "family": "unlabeled",
      "expected_rule_ids": ["PACKAGE_DATA_EXFILTRATION"],
      "expected_block": true,
      "expected_review": true
    }
  ]
}
```

Every discoverable `SKILL.md` must appear exactly once unless
`allow_unlisted_skills` is true. A benchmark config must live outside the
untrusted corpus. When no config is supplied, the harness creates an empty
trusted config and does not load a corpus-local `razin.yaml`.

## Non-vacuous gates

An enforced gate file must contain separate `block.overall` and
`review.overall` scopes. Each must set positive sample, malicious, and benign
support; nonzero precision and recall floors; a coverage-failure-rate ceiling; and
either an FPR ceiling or specificity floor. Undefined metrics fail. A status
other than `enforced` always leaves the run red.

Support floors must be positive integers. Enforced overall gates also require
precision of at least `0.5`, recall of at least `0.1`, FPR below `0.5` (or
specificity at least `0.5`), and coverage failure rate below `0.25`; checked-in gates
should be stricter. Family gates are rejected unless the manifest explicitly
declares an authoritative family mapping.

## Pinned MalSkillBench evaluation

[MalSkillBench](https://github.com/lxyeternal/MalSkillBench) is licensed for
academic research use only. Razin does not vendor or redistribute it. The real
workflow is manual-only and requires an explicit license confirmation. It pins
commit `06e083125d5ec5dd7a189dfedadfe587a70635b9`, whose expected inventory is
3,944 malicious and 4,000 benign packages.

The release does not provide an authoritative per-package family map for most
samples. All released samples therefore use family `unlabeled`.
Directory-name `CI`, `PI`, and `MIXED` suffixes are reported separately as
`filename-*` diagnostics. No family gates are allowed until an authoritative
mapping is available.

```bash
export MALSKILLBENCH_COMMIT=06e083125d5ec5dd7a189dfedadfe587a70635b9
export MALSKILLBENCH_DIR=/tmp/MalSkillBench

git init "$MALSKILLBENCH_DIR"
git -C "$MALSKILLBENCH_DIR" remote add origin \
  https://github.com/lxyeternal/MalSkillBench.git
git -C "$MALSKILLBENCH_DIR" sparse-checkout init --cone
git -C "$MALSKILLBENCH_DIR" sparse-checkout set Dataset/Skills
git -C "$MALSKILLBENCH_DIR" fetch --filter=blob:none --depth=1 origin \
  "$MALSKILLBENCH_COMMIT"
test "$(git -C "$MALSKILLBENCH_DIR" rev-parse FETCH_HEAD)" = \
  "$MALSKILLBENCH_COMMIT"
git -C "$MALSKILLBENCH_DIR" -c core.hooksPath=/dev/null \
  checkout --detach FETCH_HEAD

uv run python scripts/build_malskillbench_manifest.py \
  --skills-root "$MALSKILLBENCH_DIR/Dataset/Skills" \
  --commit "$MALSKILLBENCH_COMMIT" \
  --output /tmp/malskillbench-manifest.json

uv run python scripts/evaluate_corpus.py \
  --manifest /tmp/malskillbench-manifest.json \
  --gates benchmarks/gates/malskillbench.json \
  --output benchmark-results/malskillbench.json \
  --features-output benchmark-results/malskillbench-features.json
```

The real gate intentionally remains `review-required` until a corrected
dual-outcome report is reviewed. Changing only the status cannot make it green:
the evaluator rejects missing or zero-support thresholds.
