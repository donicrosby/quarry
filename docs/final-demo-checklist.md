# Final Demo Checklist

End-to-end steps to run the local demo and verify each artifact.
Run these in order; each step includes the expected output.

## Prerequisites

Start the following services before running the demo. Each needs its own terminal.

```bash
# Terminal 1 — Temporal server
docker compose -f docker-compose.temporal.yml up -d
# expected: containers start; Temporal UI reachable at http://localhost:8233

# Terminal 2 — Vulnerable-FastAPI target (port 9000)
task target
# expected: "target=http://127.0.0.1:9000" and "health=ok"

# Terminal 3 — Quarry server + worker (port 8000)
uv run quarry server
# expected: "Application startup complete." and worker registration logs
```

## Run the demo

```bash
task demo
```

`task demo` checks prerequisites before running. If anything is missing it prints
the exact commands and exits cleanly rather than crashing.

Expected terminal output (abbreviated):

```
Checking prerequisites...
  [ok] Temporal server reachable at http://localhost:8233
  [ok] Quarry server reachable at http://localhost:8000/healthz
  [ok] Vulnerable-FastAPI target reachable at http://localhost:9000/health

Running demo scan...
  repo:   examples/vulnerable-fastapi
  target: http://localhost:9000

scan_id=<id>  status=COMPLETED  ...
report: .quarry/reports/<id>.md
```

## Verify attack surface

```bash
uv run quarry scan list
```

Expected: one row with `status=COMPLETED` and a report path.

The Markdown report's `## Attack surface` table should include the vulnerable app's routes:
`POST /login`, `GET /users/{user_id}`, `POST /run-command`, etc.

## Verify findings

```bash
cat .quarry/reports/<scan_id>.md
```

Check for these sections in the report:

- **`## Final findings`** — at least one finding (secrets, IDOR, or command-injection).
  Each finding has:
  - Class (`secrets` / `idor` / `command_injection`)
  - Severity
  - A `#### Proof:` block with a safe payload and evidence artifact URI.

- **`## Coverage`** — shows vuln classes requested vs. completed and how many attack
  surface items were scanned vs. skipped.

- **`## Provenance`** — shows the scan manifest ID, Quarry version, and repo commit SHA.

## Verify artifacts

```bash
ls .quarry/artifacts/
ls .quarry/artifacts/integrations/jira/
ls .quarry/artifacts/integrations/slack/
```

Expected: one `.json` file per final finding in each integration subdirectory (dry-run
Jira tickets and Slack payloads, no external calls made).

## Verify TUI

While a scan is running (or after one completes):

```bash
uv run quarry tui --db .quarry/quarry.db
```

Expected: scan list with status, expandable finding rows, and progress through stages
(SNAPSHOT → ATTACK_SURFACE → SECRETS_SCAN → ... → COMPLETED).

## Verify replay

Re-render a report from stored state without re-running the scan:

```bash
uv run quarry scan rerun <scan_id>
```

Expected: report re-written to the same path. The re-rendered report includes
`## Final findings` and `## Provenance` but **omits** `## Repository snapshot` and
`## Coverage` (those artifacts are not reloaded in replay mode — known gap).

## Known gaps (honest)

- **Replay omits snapshot and coverage sections** — `RepositorySnapshot` and
  `CoverageLedger` artifacts are not persisted as reloadable DB rows, so replay
  re-renders cannot include them. Acceptable for Milestone 1.
- **Model provenance is empty** — `ModelInvocation` records exist in the schema but
  Milestone 1 scans use `MockModelClient` with no real model calls, so the provenance
  table has no model rows.
- **Flaky `ResourceWarning` on cancel** — in the cancel + snapshot integration test,
  a `ResourceWarning: Enable tracemalloc...` fires 10–30% of the time at GC collection.
  It does not affect correctness and does not appear in normal demo runs.
- **Live model calls deferred** — `MockModelClient` is used throughout; real LiteLLM
  calls are wired but require API keys and a live provider.
- **Target auto-launch deferred** — the target must be started manually with `task target`.
