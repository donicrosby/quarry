# Quarry Architecture

Quarry is a local-first agentic vulnerability research harness for source-aware web and API testing.

## Data flow

```
CLI/TUI → QuarryClient (httpx) → FastAPI server (quarry_server)
       → Temporal workflow (quarry_workflows)
       → Activities (quarry_activities)
       → SQLite (quarry_persistence) / Filesystem artifacts (quarry_artifacts)
```

## What is real

- **Attack-surface mapping** — FastAPI route extraction via Python `ast`.
- **Secrets scanning** — regex-based scanner in `quarry_plugins/vuln_classes/secrets.py`.
- **IDOR scanning** — two-user dynamic check in `quarry_plugins/vuln_classes/idor.py`.
- **Command-injection scanning** — source-to-sink detection in `quarry_plugins/vuln_classes/command_injection.py`.
- **Validation** — dynamic HTTP check against live target; produces safe local proof artifacts.
- **Provenance** — `ScanManifest`, `FindingProvenance`, model/tool invocation records.
- **Resume** — workflows checkpoint completed stages; resume skips already-completed stages.
- **Replay** — `POST /scans/{id}/replay` re-renders the Markdown report from stored findings and provenance without new scan or model calls.
- **Dry-run integrations** — Jira and Slack sinks write payload artifacts; no external calls.
- **Coverage ledger** — records which attack surface items were scanned vs. skipped and why.

## Deferred

- Real model calls in the scan path (uses `MockModelClient`).
- Automatic target launching.
- Kubernetes deployment (see `docs/kubernetes-scale-plan.md`).
- Postgres migration.
- Signed provenance / SBOM.
