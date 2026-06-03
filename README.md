# Quarry

Quarry is a local-first, Temporal-orchestrated vulnerability research harness. It scans a
Python repository for secrets, IDOR patterns, and command-injection sinks, validates each
candidate finding with dynamic checks against a live target, produces a safe local proof,
and writes a Markdown report with provenance and a coverage ledger.

## Quickstart

### Prerequisites

Start the supporting services in separate terminals:

```bash
# 1. Temporal server
docker compose -f docker-compose.temporal.yml up -d

# 2. Vulnerable-FastAPI target (port 9000)
task target

# 3. Quarry server + worker (port 8000)
uv run quarry server
```

### Run the demo

```bash
uv sync --extra dev
task demo
```

`task demo` checks that the server and target are reachable before running. If any
prerequisite is down it prints the exact commands to start it.

### What you get

After a successful scan:

- **Attack surface** — FastAPI routes extracted from the repo source.
- **Findings** — secrets, IDOR, and command-injection findings, each with a fingerprint
  and a safe local proof artifact.
- **Coverage ledger** — which files and regions were scanned and which were skipped.
- **Markdown report** — `.quarry/reports/<scan_id>.md` with findings, provenance, and
  coverage summary.
- **Dry-run integrations** — Jira and Slack delivery payloads written to
  `.quarry/artifacts/` (no external calls).

View scan status while it runs:

```bash
uv run quarry tui --db .quarry/quarry.db
```

List scans and open the report:

```bash
uv run quarry scan list
cat .quarry/reports/<scan_id>.md
```

### Re-render a report (replay)

Re-render a report from stored state without re-running the scan or making model calls:

```bash
uv run quarry scan rerun <scan_id>
```

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

## Deferred

- Live model calls in the scan path (currently uses `MockModelClient`).
- Automatic target launching.
- Kubernetes deployment (see `docs/kubernetes-scale-plan.md`).
