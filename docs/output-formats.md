# Output formats

By default, Razin writes per-skill JSON reports when `--output-dir` is set.
You can also request CSV and SARIF global exports.

## JSON

```bash
razin scan -r . -o output/ --output-format json
```

Writes per-skill artifacts:

- `output/<skill-name>/findings.json`
- `output/<skill-name>/summary.json`

JSON details:

- `findings.json` is an array of finding objects.
- Each finding includes `classification` (`security` or `informational`) and `signal_kind` (capability, review, dangerous behavior, IOC, integrity violation, attack chain, or analysis gap).
- If `rule_overrides` adjust severity (raise or cap), finding objects include `severity_override` metadata.
- `summary.json` includes:
  - `counts_by_severity`
  - `counts_by_rule`
  - `review_priority` and `review_priority_level` (triage values, not maliciousness probabilities)
  - per-skill `assessment` (`malicious/high-confidence-chain`, `risky-but-legitimate/review`, `dynamic-analysis-required/unknown`, or `clean/no-evidence`)
  - `top_risks`, ordered with actionable security evidence before contextual findings
  - deprecated compatibility aliases `overall_score` and `overall_severity`
  - optional `output_filter` metadata (`shown`, `total`, `filtered`, `min_severity`, `security_only`)
  - optional `rule_overrides` metadata
  - optional rule-selection metadata: `rules_executed`, `rules_disabled`, `disable_sources`

## CSV

```bash
razin scan -r . -o output/ --output-format csv
```

Writes:

- `output/findings.csv`

CSV columns:

- `id`
- `skill`
- `rule_id`
- `severity`
- `classification`
- `score`
- `confidence`
- `path`
- `line`
- `title`
- `description`
- `recommendation`
- `signal_kind` (appended in schema v2 so existing column positions remain stable)

## SARIF

```bash
razin scan -r . -o output/ --output-format sarif
```

Writes:

- `output/findings.sarif`

SARIF details:

- Each result includes `properties.classification` and `properties.signal_kind`.
- Capped findings include `properties.severity_override`.
- Run-level properties include:
  - `ruleDistribution`
  - optional `filter`
  - optional `ruleOverrides`
  - optional `rules_executed`, `rules_disabled`, `disable_sources`

## Multiple formats in one run

```bash
razin scan -r . -o output/ --output-format json,csv,sarif
```

## Output filters and artifacts

`--min-severity` and `--security-only` affect:

- stdout finding rows
- per-skill `findings.json`
- `findings.csv`
- `findings.sarif`

They do not change which rules run.

## Stdout grouping

```bash
razin scan -r . --group-by skill
razin scan -r . --group-by rule
```

## JSONL quiet stream

```bash
razin scan -r . --quiet-mode --quiet-output results.jsonl
```

Quiet mode writes one JSON record per line to the specified file. No stdout is emitted.

Record types:

- `finding`: one per written finding (after output filters).
- `warning`: one per scan warning (if `include_warnings` is enabled).
- `summary`: final record with transparency fields (if `include_summary` is enabled).

Each record has an envelope with `type`, `version`, `timestamp`, and `data` fields. The schema is at `schemas/quiet_stream.schema.json`.

Summary record transparency fields:

- `total_findings`: count of all findings from full scan.
- `written_findings`: count of findings written to output (after filters).
- `filtered_out_findings`: count of findings excluded by filters.
- `workspace_assessment`: workspace verdict (`contains-high-confidence-malicious`, `review-required`, `incomplete`, or `clean`).
- `assessment_counts`: number of scanned packages in each of the four per-skill assessment states.
- `gate_scope`: always `all_findings` (gate evaluation is never affected by output filters).
- `gate_failed`: boolean reflecting the exit code decision.

Config-based quiet mode:

```yaml
quiet_mode:
  enabled: true
  output_path: scan-results.jsonl
  write_mode: append
```

## Cache artifact

When output is enabled and caching is on, Razin also writes:

- `output/.razin-cache.json`
