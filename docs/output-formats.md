# Output formats

By default, Razin writes per-skill JSON reports when `--output-dir` is set.
You can also request CSV and SARIF global exports.

## JSON

```bash
uv run razin scan -r . -o output/ --output-format json
```

Writes per-skill artifacts:

- `output/<skill-name>/findings.json`
- `output/<skill-name>/summary.json`

## CSV

```bash
uv run razin scan -r . -o output/ --output-format csv
```

Writes:

- `output/findings.csv`

## SARIF

```bash
uv run razin scan -r . -o output/ --output-format sarif
```

Writes:

- `output/findings.sarif`

## Multiple formats in one run

```bash
uv run razin scan -r . -o output/ --output-format json,csv,sarif
```

## Stdout grouping

```bash
uv run razin scan -r . --group-by skill
uv run razin scan -r . --group-by rule
```

## Cache artifact

When output is enabled and caching is on, Razin also writes:

- `output/.razin-cache.json`
