# Contributing to Razin

Thanks for your interest in contributing. This guide covers everything you need to get started.

## Local setup

```bash
# Clone the repo
git clone https://github.com/theinfosecguy/razin.git
cd razin

# Install dependencies (requires Python 3.12+)
uv sync --dev
```

## Quality checks

Run these before opening a PR — they match what CI runs:

```bash
uv run isort --check-only src tests
uv run black --check src tests
uv run ruff check src tests
uv run mypy src
uv run pytest -q
```

To auto-fix formatting:

```bash
uv run isort src tests
uv run black src tests
```

## Branch and PR flow

1. Create a branch from `main` with a descriptive scope name (e.g., `feat/csv-output`, `fix/parser-edge-case`).
2. Make focused, incremental commits.
3. Push the branch and open a PR against `main`.
4. All required CI checks must pass before merge.

## Commit messages

- Single-line only.
- Start with a type prefix: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.
- Split changes into logical commits — avoid bundling unrelated files.

## PR expectations

- Title: sentence case, no type prefix (e.g., "Add CSV output format").
- Description must contain exactly two sections:
  - `## Problem Statement`
  - `## Testing` (include the test command and its output)
- Keep it concise and human-readable.

## Code style

- Type hints on public APIs and data models.
- Docstrings on modules, classes, and public functions.
- Constants in `src/razin/constants/`, exceptions in `src/razin/exceptions/`.
- Frozen dataclasses for data models.
- No decorative comment separators (`# -----`, `# =====`).
- `pathlib` for paths, pure functions in the core, side effects at the edges.
