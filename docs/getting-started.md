# Getting started

## Requirements

- Python `3.12+`
- Razin installed in your environment (`pip install razin`)

## Install

From PyPI:

```bash
pip install razin
```

Verify install:

```bash
razin --help
```

## First scan

```bash
razin scan -r . -o output/
```

This writes per-skill artifacts under `output/<skill-name>/`.

## Common scan modes

```bash
# Strict policy profile
razin scan -r . -o output/ --profile strict

# Show only summary in stdout (CI-friendly logs)
razin scan -r . -o output/ --summary-only

# Show only medium/high findings
razin scan -r . -o output/ --min-severity medium

# Show only security-classified findings
razin scan -r . -o output/ --security-only

# Combine filters
razin scan -r . -o output/ --security-only --min-severity medium
```

## CI gating examples

```bash
# Fail if any high-severity finding exists
razin scan -r . --fail-on high --no-stdout

# Fail if aggregate score is 70+
razin scan -r . --fail-on-score 70 --no-stdout

# Use summary-only output with fail gate
razin scan -r . --summary-only --fail-on medium
```

## Validate config before scanning

```bash
razin validate-config -r .
```

## Output formats

```bash
# JSON (default)
razin scan -r . -o output/ --output-format json

# CSV + SARIF + JSON in one run
razin scan -r . -o output/ --output-format json,csv,sarif
```

## Next docs to read

- [CLI flags and interactions](cli-reference.md)
- [How to write custom rules](custom-rules.md)
- [Config details and `rule_overrides`](configuration.md)
- [Output format schemas](output-formats.md)
- [CI behavior](ci-and-exit-codes.md)
