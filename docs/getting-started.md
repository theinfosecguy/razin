# Getting started

## Requirements

- Python `3.12+`
- [`uv`](https://docs.astral.sh/uv/) for local development workflows

## Install

From PyPI:

```bash
pip install razin
razin --help
```

Local development install:

```bash
uv sync --dev
razin --help
```

## Pick a scan root

Razin scans a workspace root and discovers `SKILL.md` files using configured globs.

- Default config path: `<root>/razin.yaml`
- Default skill glob: `**/SKILL.md`

Example project layout:

```text
workspace/
  razin.yaml
  skills/
    payments/SKILL.md
    support/SKILL.md
```

## First scan (write reports)

```bash
razin scan -r . -o output/
```

This writes:

- Per-skill findings: `output/<skill-name>/findings.json`
- Per-skill summary: `output/<skill-name>/summary.json`
- Cache metadata: `output/.razin-cache.json`

## Read results quickly

Run with grouped stdout output:

```bash
razin scan -r . --group-by skill
razin scan -r . --group-by rule
```

Inspect generated JSON artifacts:

```bash
cat output/<skill-name>/summary.json
cat output/<skill-name>/findings.json
```

## Validate config before scanning

```bash
razin validate-config -r .
```

For an explicit config path:

```bash
razin validate-config -r . -c ./configs/razin.yaml
```

## Common usage patterns

### Use a stricter policy profile

```bash
razin scan -r . -o output/ --profile strict --no-cache
```

### Export CSV and SARIF along with JSON

```bash
razin scan -r . -o output/ --output-format json,csv,sarif
```

### Run a CI gate (no stdout noise)

```bash
# Fail if any high-severity finding exists
razin scan -r . --fail-on high --no-stdout

# Fail if aggregate score is 70 or above
razin scan -r . --fail-on-score 70 --no-stdout
```

### Use custom rules

Replace bundled rules with a custom directory:

```bash
razin scan -r . -R ./enterprise-rules --rules-mode replace
```

Overlay custom rules on top of bundled rules:

```bash
razin scan -r . -R ./enterprise-rules --rules-mode overlay --duplicate-policy override
```

## Important flag constraints

- `--rules-dir` and `--rule-file` are mutually exclusive.
- `--duplicate-policy` is valid only with `--rules-mode overlay`.
- `--fail-on-score` must be between `0` and `100`.
- `--output-format` accepts only `json`, `csv`, `sarif`.

## Next reads

- Full CLI behavior and edge cases: `docs/cli-reference.md`
- Config tuning and precedence rules: `docs/configuration.md`
- Rule internals and scoring: `docs/detectors.md`
- CI workflow examples: `docs/ci-and-exit-codes.md`
