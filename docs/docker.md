# Docker

Use Docker for reproducible scanner execution without requiring local Python tooling.

Razin's `Dockerfile` has three stages:

- `builder`: builds the wheel artifact
- `dev`: installs dev/test dependencies via `uv sync --dev --frozen`
- `runtime`: minimal runtime image with `razin` CLI entrypoint

## Build images

Runtime image:

```bash
docker build -t razin:runtime .
```

Dev image (for tests/lint in container):

```bash
docker build --target dev -t razin:dev .
```

## Basic runtime usage

The runtime image uses `ENTRYPOINT ["razin"]`, so pass subcommands directly.

```bash
docker run --rm razin:runtime --help
docker run --rm razin:runtime scan --help
docker run --rm razin:runtime validate-config --help
```

## Scan a mounted workspace

```bash
docker run --rm \
  -v "$(pwd)":/work \
  -w /work \
  razin:runtime \
  scan --root /work --output-dir /work/output/docker
```

## CI-style gate in Docker

```bash
docker run --rm \
  -v "$(pwd)":/work \
  -w /work \
  razin:runtime \
  scan \
    --root /work \
    --output-dir /work/output/ci \
    --profile strict \
    --fail-on medium \
    --fail-on-score 50 \
    --no-stdout
```

## Config and custom rule mounting

```bash
docker run --rm \
  -v "$(pwd)":/work \
  -w /work \
  razin:runtime \
  scan \
    --root /work \
    --config /work/configs/razin.yaml \
    --rules-dir /work/enterprise-rules \
    --rules-mode overlay \
    --duplicate-policy override \
    --output-dir /work/output/docker
```

## File permission model

The runtime image runs as a non-root `razin` user.
On Linux bind mounts, this can fail if `/work/output` is not writable by that user.

Option 1: pre-create writable output path on host.

```bash
mkdir -p output/docker
chmod u+w output/docker
```

Option 2: run container with host UID/GID mapping.

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$(pwd)":/work \
  -w /work \
  razin:runtime \
  scan --root /work --output-dir /work/output/docker
```

## Use dev image for test/lint parity

```bash
docker run --rm \
  -v "$(pwd)":/work \
  -w /work \
  razin:dev \
  uv run pytest -q
```

```bash
docker run --rm \
  -v "$(pwd)":/work \
  -w /work \
  razin:dev \
  uv run ruff check src tests
```

## Debugging container environment

Open a shell in runtime image:

```bash
docker run --rm -it --entrypoint /bin/sh razin:runtime
```

Inspect CLI version in container:

```bash
docker run --rm razin:runtime --version
```
