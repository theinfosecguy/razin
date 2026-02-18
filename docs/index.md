# Razin documentation

Razin is a static analysis scanner for `SKILL.md`-defined agent skills.
It scans skill definitions, applies detector rules, and writes deterministic reports.

## Quick start

```bash
uv run razin scan -r . -o output/
```

## What to read next

- New users: [Getting Started](getting-started.md)
- Daily CLI usage: [CLI Reference](cli-reference.md)
- Policy tuning: [Configuration](configuration.md)
- Rule coverage: [Detectors](detectors.md)
- CI integration: [CI and Exit Codes](ci-and-exit-codes.md)
- Deployment and local parity: [Docker](docker.md)
- Common failures: [Troubleshooting](troubleshooting.md)

## Canonical docs policy

- `docs/` is the canonical source for full documentation.
- Root `README.md` is quick start only and links here for full details.
