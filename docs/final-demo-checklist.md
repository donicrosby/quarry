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

## Verify recon workflow (Week 11 addition)

Run `ReconWorkflow` directly against the Node target:

```bash
# Temporal + server must be running (see Prerequisites above)
uv run quarry scan run --repo examples/vulnerable-express
```

Or trigger the workflow via the Temporal CLI if the server is up:

```bash
# Check ArchitectureDoc for the JS target
python3 -c "
import asyncio
from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from quarry_workflows.recon import ReconWorkflow
async def main():
    client = await Client.connect('localhost:7233', data_converter=pydantic_data_converter)
    result = await client.execute_workflow(
        ReconWorkflow.run,
        args=['examples/vulnerable-express', 'demo-recon'],
        id='demo-recon-001',
        task_queue='quarry-control',
    )
    print(result.model_dump_json(indent=2))
asyncio.run(main())
"
```

Expected `ArchitectureDoc` output:

- `primary_language: "javascript"`
- `repo_type: "web_service"` (or `"mixed"`)
- At least one subsystem
- Non-empty `attack_surface_summary`

Run again against `examples/vulnerable-fastapi`:

```bash
python3 -c "
# ... same as above but args=['examples/vulnerable-fastapi', 'demo-recon-py']
"
```

Expected: `primary_language: "python"` without changing any harness code.

Verify `--focus` limits the scan:

```bash
uv run quarry scan run --repo examples/vulnerable-fastapi --focus ssrf,xss
# Expected: command succeeds, exits fast with focus set to ssrf + xss

uv run quarry scan run --repo examples/vulnerable-fastapi --focus bogus
# Expected: immediate exit with error listing valid class names
```

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
- **Recon uses MockModelClient** — `recon_subsystem_activity` runs `run_agent_loop` backed by `MockModelClient`; real provider wiring is a later milestone. The `ArchitectureDoc` produced by the current implementation is the result of heuristic analysis in the orchestrator, not real multi-turn reasoning.
- **`--focus` filters scan stages** — `vuln_classes` is now threaded end-to-end from
  the CLI flag through the server API into `ScanProfile`. Each scan stage (SECRETS,
  IDOR, CMDI) is gated on membership in `scan.profile.vuln_classes`. The default
  profile includes all three classes.
- **`ArchitectureDoc` is persisted** — `ReconWorkflow` saves the result to the
  `architecture_docs` SQLite table via the `save_architecture_doc` operation on the
  `persist-scan-state` activity. `QuarryRepository.load_architecture_doc(scan_id)`
  retrieves it.
