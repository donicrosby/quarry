# 2026-06-02 Dev Log — Week 9: Hardening, provenance, replay, resume

## What changed

- **Provenance schemas** (`src/quarry/schemas.py`): `ScanManifest`,
  `ToolInvocation`, `FindingProvenance`, `ReportProvenance`. Manifest captures
  quarry version, profile, active plugins, and repo commit; the rest tie findings
  and the report back to it.
- **Persistence** (`repositories.py`): `ScanManifestRecord` / `ToolInvocationRecord`
  (scan-scoped, merge upserts) with save/load methods and `persist-scan-state`
  ops in `quarry_activities/repo.py`.
- **Recording** : a new `build-scan-manifest` activity (`provenance.py`) runs at
  scan start (version via `importlib.metadata`, commit via `git rev-parse`),
  persisted and threaded into the report. The diff workflow records its `git diff`
  as a `ToolInvocation` (args hashed, exit code, timing). The report now renders a
  `## Provenance` section (manifest id, version, commit, per-finding validation /
  proof refs). Registered the activity in worker, server, and conftest.
- **Failure handling** (`run_scan.py`): on a non-cancellation exception, persist
  `ScanStatus.FAILED` with a flattened error string (walks the exception chain so
  Temporal's generic "Activity task failed" is replaced by the root cause) before
  re-raising. `ScanSummary` + `list_scan_summaries` gained an `error` field (new DB
  column) and the TUI dashboard shows an Error column.
- **Replay** : `POST /scans/{id}/replay` re-renders the report from persisted
  findings / attack surface / manifest by reusing the render activity in a worker
  thread — no workflow, no scan stages, no model/tool calls. Added
  `client.replay_scan` and `quarry scan rerun <id> --mode replay`.
- **Snapshot cancellation**: `build_file_manifest` is now cancellation-aware
  (mirrors the secrets scanner) and the snapshot activity waits for cancellation to
  complete, so a cancelled snapshot stops promptly instead of reading every file.

## Retry / recovery rationale

- Activities keep `maximum_attempts=1` (fail fast). The recovery model is
  **idempotent resume**, not automatic retry: scan state is checkpointed per stage
  (`COMPLETED_STAGE_ORDER`), findings use scan-scoped composite keys + `merge`
  upserts, and integration delivery is idempotency-keyed. So re-running a scan with
  `resume=True` reloads completed stages and never duplicates findings or
  integration runs (locked by `test_e2e_resume_does_not_duplicate_findings`).
- Replay is the read-only sibling of resume: it recomputes nothing, it just
  re-renders from stored state. In Milestone 1 scans make no model calls, so
  `ModelInvocation` provenance is structurally present but unpopulated; the
  representative recorded tool is the diff workflow's `git`.

## What works

- `ruff check` / `ruff format --check` / `pyright` clean (0/0/0).
- `pytest -q -W default`: 325 passed. (One known flaky `ResourceWarning` — see
  below — is non-failing.)
- Replay re-renders a report containing the finding and the `## Provenance` section
  without starting a workflow or appending events.
- A forced activity failure leaves the scan `FAILED` with the root-cause error,
  visible via `list_scan_summaries` / TUI, with the manifest + earlier artifacts
  preserved.

## What is broken

- Flaky `ResourceWarning: unclosed file <BufferedReader … module_NNN.py>` in the
  cancel e2e (snapshot `read_bytes` during a teardown race). It fires at GC time
  (so `-W error::ResourceWarning` does not catch it) at ~10–30% frequency. The
  snapshot cancellation-awareness reduced but did not eliminate it. Deferred to a
  follow-up; partial fix kept because it is correct on its own.
- Coverage ledger, proof artifacts, and the repo snapshot are not persisted as
  reloadable rows, so a replayed report omits those sections. Acceptable for the
  demo; persistence is a later concern.

## Next command to run

```bash
uv run quarry server &
uv run quarry scan run --repo examples/vulnerable-fastapi --target http://localhost:9000
uv run quarry scan rerun <scan_id> --mode replay   # re-renders from stored state
```

## Next task

- Eliminate the cancel-snapshot `ResourceWarning` at the source.
- Week 10 per the planning docs.

## Open decisions

- Replay reuses the render activity in-process (a worker thread) rather than
  spawning a render-only workflow — simpler, and it provably runs no scan stages.
