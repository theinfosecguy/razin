# Getting started

## Requirements

- Python `3.12+`
- [`uv`](https://docs.astral.sh/uv/) for local development workflows

## Install

From PyPI:

```bash
pip install razin
```

Local development install:

```bash
uv sync --dev
```

## First scan

```bash
uv run razin scan -r . -o output/
```

This writes per-skill JSON artifacts under `output/<skill-name>/`.

## Validate config before scanning

```bash
uv run razin validate-config -r .
```

## Useful follow-up commands

```bash
uv run razin scan -r . --profile strict --no-cache
uv run razin scan -r . --fail-on high --no-stdout
uv run razin scan -r . --output-format json,csv,sarif
```
