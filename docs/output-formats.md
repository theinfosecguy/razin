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
- Each finding includes `classification` (`security` or `informational`).
- If `rule_overrides` adjust severity (raise or cap), finding objects include `severity_override` metadata.
- `summary.json` includes:
  - `counts_by_severity`
  - `counts_by_rule`
  - optional `output_filter` metadata (`shown`, `total`, `filtered`, `min_severity`, `security_only`)
  - optional `rule_overrides` metadata

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

## SARIF

```bash
razin scan -r . -o output/ --output-format sarif
```

Writes:

- `output/findings.sarif`

SARIF details:

- Each result includes `properties.classification`.
- Capped findings include `properties.severity_override`.
- Run-level properties include:
  - `ruleDistribution`
  - optional `filter`
  - optional `ruleOverrides`

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

## Cache artifact

When output is enabled and caching is on, Razin also writes:

- `output/.razin-cache.json`
