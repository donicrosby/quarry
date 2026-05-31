# Quarry

Quarry is a local-first, Python-first, Temporal-based vulnerability research harness.

The current walking skeleton takes a repository path, persists a fake candidate finding, writes a Markdown report, and displays scan status in a read-only TUI.

## Quickstart

```bash
uv sync --extra dev
uv run quarry scan run --repo .
uv run quarry tui --db .quarry/quarry.db
```

## Current demo

```bash
uv run quarry scan run --repo .
```

This creates:

- `.quarry/quarry.db`
- `.quarry/reports/<scan_id>.md`

Real:

- Pydantic schemas
- SQLite persistence
- Markdown report rendering
- CLI and read-only TUI surface
- Temporal workflow and worker definitions

Fake or stubbed:

- Vulnerability discovery
- Validation and proof
- Model calls
- Target launching

## Development

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pre-commit run --all-files
```

Install local hooks with:

```bash
uv run pre-commit install
uv run pre-commit install --hook-type commit-msg
```
