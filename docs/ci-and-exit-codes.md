# CI and exit codes

Razin supports CI gating by severity threshold and aggregate score.

## Exit code controls

```bash
# Fail if any high-severity finding exists
razin scan -r . --fail-on high --no-stdout

# Fail if aggregate score is 70 or above
razin scan -r . --fail-on-score 70 --no-stdout

# Either condition can fail the job
razin scan -r . --fail-on medium --fail-on-score 50 --no-stdout
```

## Display filters vs gating

Display filters do not alter scanner execution:

- `--min-severity`
- `--security-only`
- `--summary-only`

Gating behavior:

- `--fail-on` evaluates against full scan findings (after rule overrides).
- `--fail-on-score` evaluates the aggregate score from full findings (after rule overrides).

Example:

```bash
# Output only medium/high rows, but still fail if any low finding exists
razin scan -r . --min-severity medium --fail-on low --no-stdout
```

## Rule overrides and CI

`rule_overrides` in config are policy-level controls and do affect CI thresholds.

```yaml
rule_overrides:
  MCP_REQUIRED:
    max_severity: low
```

With this override, `MCP_REQUIRED` findings are capped before fail checks run.

Rule-disable controls also affect CI because disabled rules do not execute:

```yaml
rule_overrides:
  MCP_REQUIRED:
    enabled: false
```

Equivalent one-run CLI controls:

```bash
razin scan -r . --disable-rule MCP_REQUIRED
razin scan -r . --only-rules SECRET_REF --only-rules OPAQUE_BLOB
```

## Rulepack composition in CI

```bash
# Merge enterprise rules and fail on duplicate IDs
razin scan -r . -R ./enterprise-rules --rules-mode overlay --duplicate-policy error

# Merge enterprise rules and let custom duplicates override bundled rules
razin scan -r . -R ./enterprise-rules --rules-mode overlay --duplicate-policy override
```

## Example GitHub Actions step

```yaml
- name: Run Razin gate
  run: |
    razin scan \
      --root . \
      --output-dir output/ \
      --profile strict \
      --summary-only \
      --fail-on medium \
      --fail-on-score 50
```

## Quiet mode in CI

Quiet mode is designed for CI and automation pipelines that need machine-ingestible output without terminal noise.

```bash
razin scan -r . --quiet-mode --quiet-output results.jsonl --fail-on medium
```

**Gotcha**: Output filters (`--min-severity`, `--security-only`) affect only what gets written to the quiet output file. Gate evaluation (`--fail-on`, `--fail-on-score`) always uses all findings from the full scan. The quiet summary record includes `gate_scope: "all_findings"` for auditability.

Quiet mode rejects conflicting output flags: `-o`, `--output-format`, `--group-by`, `--summary-only`. Use config-based quiet mode for persistent settings:

```yaml
quiet_mode:
  enabled: true
  output_path: scan-results.jsonl
  write_mode: overwrite
```

## Docs CI checks in this repository

```bash
uv run mkdocs build --strict
uv run mdformat --check README.md docs
```

Link checks run in CI workflow against `README.md` and `docs/` markdown files.
