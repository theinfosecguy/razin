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

## Docs CI checks in this repository

```bash
uv run mkdocs build --strict
uv run mdformat --check README.md docs
```

Link checks run in CI workflow against `README.md` and `docs/` markdown files.
