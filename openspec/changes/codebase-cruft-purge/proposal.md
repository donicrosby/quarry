# Change: codebase-cruft-purge

## Why

The codebase has accumulated sprawl and dead weight that now actively costs time and produces bugs — and the core scan loop's architecture makes scans far slower than the workload requires:

- **`src/quarry_workflows/run_scan.py` is ~3989 lines** — a god-module mixing orchestration, coverage logic, dedup wiring, event emission, and promotion policy. Every pipeline change (the SSRF sweep, the mitigation gate, dedup cutover) required surgery in this one file, and several past defects traced to edits colliding inside it.
- **The scan pipeline is barrier-serialized.** The round loop runs hunt → dedup → validate in discrete phases per round: every candidate waits for its entire round's hunt tasks to finish, then waits for the round's dedup pass, then enters a sequential per-candidate validation loop. A candidate produced in the first 30 seconds of a round sits idle until the slowest hunter in that round finishes; validation of 7 candidates runs strictly one-at-a-time even though the calls are independent. On the 2026-09-16 verification scan this design cost ~90 minutes of wall-clock on a repo with 4 real vulnerabilities — nearly all of it candidates waiting at stage barriers, and validation serialized behind a flaky provider's retry backoff.
- **Dead code that looks alive**: `_only_non_mitigation_args` in `mitigation_gate.py` was an orphaned helper whose body referenced a module constant that had been partially excised — it sat there compiling because nothing called it, and it mangled the file when a later edit assumed it was live.
- **Hand-counted invariants in multiple places**: activity registration is asserted as a literal (`== 33`) in `test_server_lifespan.py` and must be bumped by hand on every new activity; the count lives nowhere near the registry.
- **537 imports across `src/quarry_activities/`** alone, 15 top-level `quarry_*` packages — the layering is real but nobody has audited what's actually used.
- Prompt templates, panel configs, and profile defaults (`local-fast` hardcoding 3 classes) scattered with no single inventory.

None of this is user-visible, but it slows every subsequent change, has already shipped bugs, and — in the barrier architecture — directly burns wall-clock and money on every scan.

## What Changes

Two coupled efforts: a **streaming pipeline re-architecture** of the scan loop, and a **pure refactor** cleanup pass. The re-architecture changes timing and concurrency (observable: scans complete faster, per-candidate events arrive earlier) but must not change verdicts, dedup outcomes, budgets, or report content — same inputs produce the same final findings.

### 1. Streaming pipeline (replaces barrier-per-round)

Restructure the scan loop from "hunt round → dedup round → validate round" into a **producer-consumer pipeline** where candidates flow forward as soon as they exist:

- **Candidates stream, not batch.** As each hunt task / sweep / live-exploitation produces a candidate, it is immediately persisted and enqueued for the next stage — it does not wait for sibling hunt tasks or the round boundary.
- **Stage barriers only where the operation is inherently a set operation:**
  - **Dedup** is a legitimate funnel: a candidate's dedup decision depends on the candidate set so far. Dedup becomes a *streaming merge* (each new candidate checked against the accumulated set as it arrives) rather than a per-round batch pass. Set-membership check is per-candidate; no barrier needed beyond a lock/queue on the accumulated set.
  - **Validation** (reasoner + debater ensemble) is per-candidate and independent → runs **concurrently** (bounded by a semaphore sized to panel rate limits), not sequentially. This is the single biggest wall-clock win.
  - **Coverage-ledger / gapfill round decisions** genuinely need a round-level view (which classes have candidates, which are exhausted) → these remain round-scoped, but rounds no longer gate *validation* — only *re-hunting*.
  - **Budget accounting** is a global funnel — checked atomically per model invocation as today.
- **Early termination**: when the coverage ledger saturates and in-flight validations complete, the scan finishes without waiting for round caps.
- **Retry/backoff trim**: validation retry backoff moves from minutes-scale to seconds-scale with jitter — provider failover at the proxy makes long sleeps pure waste; fail fast, let the proxy route around the dead deployment.

Temporal constraints apply: the workflow remains deterministic (all concurrency via `asyncio` inside activities or via child-workflow fan-out, never raw threads; replay-safe). The design must decide — and document — which stages stay in the monolith workflow vs. split into per-candidate child workflows; preference is in-workflow `asyncio` concurrency for validation, since candidates already live in workflow state.

### 2. Dead-code audit and deletion

- Run a dead-code pass (`vulture` or equivalent, plus pyright's unused-symbol reporting) across `src/`; every candidate is verified unreferenced (including string references, activity names, plugin entry points) before deletion.
- Delete orphaned helpers, unused imports, stale comments referencing removed code.

### 3. `run_scan.py` decomposition

The streaming re-architecture (item 1) forces this split — execute them together, extraction-first where feasible:

- Extract cohesive stages into modules: candidate sources/sweeps, streaming dedup, concurrent validation pool, coverage ledger ops, promotion wiring, event emission.
- Where a stage is only being moved (not re-architected), no logic edits during the move — relocate, fix imports, run the suite.

### 4. Invariant consolidation

- Replace hand-counted literals (activity count `== 33`, similar) with assertions derived from the registry itself, or generate the expected count at test time from the source of truth.
- Single inventory for prompt templates / panel config / profile defaults where they currently scatter.

### 5. Guardrails

- CI gate: `vulture` (allowlist for intentional dynamic references) or pyright strict-unused on changed files, so cruft stops re-accumulating.
- Benchmark gate: a standardized scan of `examples/vulnerable-fastapi` must complete in ≤ N minutes wall-clock (N set from post-refactor measurement, target roughly half the pre-change duration), and produce **identical final findings** to the pre-change baseline run — the streaming rework's regression contract.

## Impact

- **Specs**: none (`skip_specs: true` — code-only; pipeline timing is not a spec-level contract, and final-finding equivalence is enforced by tests/benchmark rather than spec deltas).
- **Code**: `src/quarry_workflows/run_scan.py` re-architected and split; deletions across `src/quarry_activities/`, `src/quarry_models/`, `src/quarry_tools/`; test-literal replacements; validation concurrency pool; retry/backoff policy.
- **Risk**: moderate-high (concurrency + Temporal determinism is a real correctness surface) — mitigated by the existing 1900+ unit suite, integration suite, golden tests, and a **deterministic replay check**: the streaming workflow's event history must replay cleanly, and the final findings on the vulnerable-fastapi benchmark must match the pre-change run exactly.
- **Behavior contract**: verdicts, dedup results, budget enforcement, and report contents unchanged for identical inputs. What changes is *when* work happens, not *what* work happens. Event ordering in the stream may differ (per-candidate events arrive earlier); consumers of the event log must not depend on stage-grouped ordering — audit for any such dependency during implementation.
- **Non-goals**: prompt/template content edits, dependency upgrades, changes to model panels or scoring logic, re-architecture beyond the scan pipeline (server, integrations, CLI stay as-is).
