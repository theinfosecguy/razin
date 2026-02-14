# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN python -m pip install --no-cache-dir --upgrade pip build

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m build --wheel --outdir /dist


FROM python:3.12-slim AS dev

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy

WORKDIR /work

RUN python -m pip install --no-cache-dir --upgrade pip uv

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY tests ./tests

RUN uv sync --dev --frozen


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /work

RUN addgroup --system razin && \
    adduser --system --ingroup razin --home /home/razin razin

COPY --from=builder /dist/*.whl /tmp/

RUN python -m pip install --no-cache-dir /tmp/*.whl && \
    rm -f /tmp/*.whl

USER razin

ENTRYPOINT ["razin"]
