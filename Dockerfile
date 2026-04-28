# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    CDP_DATA_DIR=/app/data

WORKDIR /app

# Copy project metadata + package source. The compose file bind-mounts
# ./cdp on top of /app/cdp at runtime so host edits propagate.
COPY pyproject.toml README.md ./
COPY cdp/ ./cdp/

# Editable install + dev extras (ruff, mypy, pytest).
RUN pip install -e '.[dev]'

# Bind-mount target (compose mounts ./data over this).
RUN mkdir -p /app/data

# Default to the CLI help screen; users override with
# `docker compose run --rm cdp cdp ingest --synthetic` etc.
CMD ["cdp", "--help"]
