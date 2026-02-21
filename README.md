<h1 align="center">Razin - Static analysis for LLM agent skills</h1>

<p align="center">
  <img src="https://github.com/user-attachments/assets/33c42667-0fff-4eac-a2d1-0f6d10441245" alt="razin" width="300" height="300" />
</p>

Razin is a local scanner for `SKILL.md`-defined agent skills.
It performs static analysis only (no execution) and writes deterministic findings.

## Table of contents

- [Documentation](#documentation)
- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
  - [Common CI gates](#common-ci-gates)
  - [Output formats](#output-formats)
- [Local development](#local-development)
- [Where to read more](#where-to-read-more)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Documentation

Full documentation lives at:

- https://theinfosecguy.github.io/razin/

Canonical docs source in this repository:

- `docs/`

Use this README for quick start only.

## Requirements

- Python `3.12+`

## Install

With Homebrew (current, via tap):

```bash
brew tap theinfosecguy/homebrew-tap
brew install razin
razin --help
```

With PyPI:

```bash
pip install razin
razin --help
```

## Quick start

Run a scan:

```bash
razin scan -r . -o output/
```

Validate config:

```bash
razin validate-config -r .
```

### Common CI gates

```bash
# Fail if any high-severity finding exists
razin scan -r . --fail-on high --no-stdout

# Fail if aggregate score is 70 or above
razin scan -r . --fail-on-score 70 --no-stdout
```

### Output formats

```bash
# Default per-skill JSON reports
razin scan -r . -o output/ --output-format json

# Add CSV + SARIF exports
razin scan -r . -o output/ --output-format json,csv,sarif
```

## Local development

```bash
uv sync --dev
uv run pytest -q
uv run ruff check src tests
uv run mypy src tests
```

Docs preview and checks:

```bash
uv sync --group docs
uv run mkdocs serve
uv run mkdocs build --strict
uv run mdformat --check README.md docs
```

## Where to read more

- [Getting started](https://theinfosecguy.github.io/razin/getting-started/)
- [CLI reference](https://theinfosecguy.github.io/razin/cli-reference/)
- [Configuration](https://theinfosecguy.github.io/razin/configuration/)
- [Detectors](https://theinfosecguy.github.io/razin/detectors/)
- [Output formats](https://theinfosecguy.github.io/razin/output-formats/)
- [Docker workflow](https://theinfosecguy.github.io/razin/docker/)
- [CI and exit codes](https://theinfosecguy.github.io/razin/ci-and-exit-codes/)
- [Troubleshooting](https://theinfosecguy.github.io/razin/troubleshooting/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
