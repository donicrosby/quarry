# syntax=docker/dockerfile:1
#
# Single image for both the Quarry server (`quarry server --no-worker`) and the
# Quarry worker (`quarry worker`) — identical code + deps, different command.
#
# All pinned versions are build ARGs (single source of truth; override via
# `--build-arg` or compose `build.args`). No version literals appear inline.
ARG PYTHON_VERSION=3.12-slim-bookworm
ARG UV_VERSION=0.9.21
ARG AST_GREP_VERSION=0.43.0
ARG OPENGREP_VERSION=v1.22.0

# uv binary as a named stage — `COPY --from` cannot expand a variable in an image
# ref, but `FROM` can, so we pin uv here and copy from this stage below.
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uvbin

# --------------------------------------------------------------------------
# tools: fetch the pinned scanner binaries (arch-aware: amd64 in CI, arm64 on
# Apple Silicon). The hunters shell out to `ast-grep` and `opengrep`; `git` and
# `ripgrep` come from apt in the runtime stage.
# --------------------------------------------------------------------------
FROM debian:bookworm-slim AS tools
ARG AST_GREP_VERSION
ARG OPENGREP_VERSION
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) ag_asset="app-x86_64-unknown-linux-gnu.zip"; og_asset="opengrep_manylinux_x86" ;; \
      arm64) ag_asset="app-aarch64-unknown-linux-gnu.zip"; og_asset="opengrep_manylinux_aarch64" ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/ast-grep/ast-grep/releases/download/${AST_GREP_VERSION}/${ag_asset}" -o /tmp/ast-grep.zip; \
    unzip -o /tmp/ast-grep.zip -d /tmp/ast-grep; \
    install -m 0755 /tmp/ast-grep/ast-grep /usr/local/bin/ast-grep; \
    curl -fsSL "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${og_asset}" -o /usr/local/bin/opengrep; \
    chmod 0755 /usr/local/bin/opengrep

# --------------------------------------------------------------------------
# builder: resolve + install dependencies and the project into /app/.venv.
# Two syncs so the heavy dependency layer is cached until uv.lock changes.
# --------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS builder
COPY --from=uvbin /uv /bin/uv
ENV UV_PYTHON_PREFERENCE=only-system \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
WORKDIR /app
# Dependency layer: needs only the lock + metadata, so it stays cached across
# source edits.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev
# Project layer: install Quarry itself (editable, into the same venv).
COPY src ./src
COPY prompts ./prompts
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# --------------------------------------------------------------------------
# runtime: slim image with git + ripgrep (apt) and ast-grep + opengrep (tools).
# --------------------------------------------------------------------------
FROM python:${PYTHON_VERSION} AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git ripgrep ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY --from=tools /usr/local/bin/ast-grep /usr/local/bin/opengrep /usr/local/bin/
RUN useradd --create-home --uid 1000 quarry \
    && mkdir -p /data \
    && chown quarry:quarry /data
WORKDIR /app
# The project is installed editable, so the runtime needs src/ + prompts/ on disk.
# The prompt registry resolves prompts_root as <pkg>/../../prompts == /app/prompts.
COPY --from=builder /app/.venv /app/.venv
COPY pyproject.toml README.md ./
COPY src ./src
COPY prompts ./prompts
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    QUARRY_SERVER_HOST=0.0.0.0 \
    QUARRY_DB_PATH=/data/quarry.db
EXPOSE 8000
VOLUME ["/data"]
USER quarry
# Default to the API server with its embedded worker disabled; the dedicated
# worker service owns the Temporal task queue (avoids a dual-worker race).
CMD ["quarry", "server", "--no-worker"]
