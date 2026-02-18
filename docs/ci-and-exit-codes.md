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
      --fail-on medium \
      --fail-on-score 50 \
      --no-stdout
```

## Docs CI checks in this repository

```bash
uv run mkdocs build --strict
uv run mdformat --check README.md docs
```

Link checks run in CI workflow against `README.md` and `docs/` markdown files.
