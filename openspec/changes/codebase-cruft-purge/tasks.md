# Tasks: codebase-cruft-purge

Code-only change (`skip_specs: true`). The full test suite (unit + integration + golden) plus a **final-findings-equivalence benchmark** on `examples/vulnerable-fastapi` is the behavior contract; every step lands green before the next begins.

> **2026-09-29 audit update:** tasks below rewritten from the verified audit
> (`.hermes/plans/2026-09-29_cruft-audit-SYNTHESIS.md`, 4 read-only audit slices,
> claims re-verified against source). Facts that changed: PR #54 already landed
> per-stage fan-out; the activity-count literal is already registry-derived
> (#51); the only verified-dead symbol is `run_fake_scan`; the vulture 60% list
> is false positives (pydantic validators + `@activity.defn` registry); NEW
> spec-conformance defects found (§2). `run_scan.py` is now 4307 lines.

## 1. Baseline
- [x] 1.1 Record baseline: full unit + integration + golden suites green on the starting commit; ruff/pyright clean *(CI green on main `8493e44` run 36284287521; re-confirm on landing commit)*
- [x] 1.2 Record baseline scan: `examples/vulnerable-fastapi` — DONE: scan `0ca28ec3`, snapshot at `.quarry/baseline-0ca28ec3.json` ($0.69, 124 invocations, 12 finals across all 4 GT classes, ~90 min wall-clock). NOTE: scan status=failed on a `calibrate-finding` StartToClose 61s timeout during a host OOM window (findings were recorded pre-failure; Temporal resume verified). The 61s calibrate timeout is flagged borderline vs chutes latency — revisit under §3.7
- [x] 1.3 Snapshot current `run_scan.py` structure — DONE: 4307 lines, 86 functions, `_run` 735L, `_run_round` 1150L, 35 activity call sites, 55 event emission sites, 5 semaphore fan-outs; import-hub status (6 golden tests + back-compat re-exports `:112-130`). See audit synthesis §3
- [ ] 1.4 Audit event-log consumers for stage-grouped ordering assumptions (streaming changes event interleaving) — consumers: TUI, integrations sinks, report/replay, SSE clients, tests

## 2. Spec-conformance fixes (NEW — do these first; mechanical, low-risk)
- [x] 2.1 SPEC-D1: persist-before-advance for VALIDATION, GAPFILL, COVERAGE — DONE: added `_persist_scan_stage` at all three (VALIDATION after HUNT's secrets gate; GAPFILL after `gapfill.completed`; COVERAGE after `_record_coverage`). Decision (design.md): keep VALIDATION in `COMPLETED_STAGE_ORDER` (fold would churn pinned tests for one persist call). Note: resume *gates* for these stages are implicit — `_stage_completed` order-comparison now sees their markers
- [x] 2.2 ADR-D3: round-scoped resume — DONE: (a) `AgentTaskRecord` table + real `save_agent_task`/`load_agent_tasks` (was a documented no-op; merge-idempotent, ordered (round_index, id)); (b) round marker `ROUND:<n>:TRACER` persisted at each round's tracer completion; (c) `_round_cursor_from_stage` decodes marker → start round (plain markers=0, round markers=n+1, post-loop=LOOP_DONE skip); (d) loop re-queues persisted `next_tasks` at loop bottom; resume reloads tasks with `round_index >= cursor` and emits `loop.resumed`. Tests: test_agent_task_persistence.py (6), test_round_resume.py (3). design.md documents contract + non-goals (mid-stage resume in round>0, hunter_gaps recompute-empty)
- [x] 2.3 Remove in-function imports in `run_scan.py` (own-rule violation): `:578` (`from quarry.schemas import Subsystem as _Subsystem` — hoist; `SubsystemAssignment` already imported at top), `:3799` (`import json as _json` — shadows module-level `json` from line 4)
- [x] 2.4 Replace hand-counted `len(worker.workflows) == 4` (`test_server_lifespan.py:76`) with a registry/derived assertion (activity-count equivalent already done in #51)
- [x] 2.5 Raw-string bypasses of spec-backed schemas: `'oos'` literal in `run_scan.py` → `TriageLabel`; `"none"/"repo_readonly"` in `sandbox_tool.py:49-51,90` → `EnvProfile`; verdict vocabulary typing — landed: `'oos'` → `TriageLabel.OOS`, `EnvProfile` wiring (byte-identical wire format), and `EnsembleJudgement.verdict: str` → `JudgementVerdict` StrEnum (VALIDATED/REJECTED/REFUTED/UNREFUTED) with byte-identical JSON pinned by regression test + parse-boundary tolerance for unknown/empty model verdicts (`EnsembleJudgement` schema-level coercion; `CandidateFinding` carries no raw `verdict` field — posture is `status`/`credibility`/`ensemble`, so no Literal alignment needed there)

## 3. Streaming pipeline re-architecture
> PR #54 (scan-stage-fanout) already landed: semaphore fan-out for AGENTIC_VALIDATE (mid-batch `_VALIDATE_COST_INCREMENT_USD=0.05`), TRACER, CALIBRATE, live-exploitation, and class-parallel inventory chains. Remaining serialization (verified):

- [ ] 3.1 Hunt-barrier streaming: candidates currently wait for `asyncio.gather` over ALL round hunters before any flows to dedup/validate (`_run_round` HUNT block) — persist + enqueue each hunter's candidates as its task resolves, keep post-gather event emission input-order for replay safety
- [ ] 3.2 PROVE fan-out: serial `for finding in prioritize_by_live_verdict(...)` loop (`run_scan.py:2291`), up to `PROVE_MAX_ATTEMPTS` sandbox runs each — mirror the #54 semaphore pattern + concurrency-contract tests
- [ ] 3.3 Secrets-gate fan-out: `validate-secret-candidate` (30s timeout) runs serially inside the HUNT candidate loop (`:1551+`) — fan or fold under the validate pool
- [ ] 3.4 Streaming dedup: per-candidate merge against accumulated set on arrival (replace per-round batch pass at `:2201`) — dedup is a legitimate funnel, keep it a set operation
- [ ] 3.5 Round scoping retained ONLY for coverage-ledger / gapfill / feedback re-hunt decisions (ADR-022 verified implemented and replay-safe — do not break the edges); validation no longer gated on rounds
- [ ] 3.6 Early termination: coverage saturated + in-flight validations drained → finish, no round-cap wait
- [ ] 3.7 Retry/backoff: minutes-scale → seconds-scale with jitter (fail fast, let proxy failover route around dead deployments); revisit `calibrate-finding` 61s StartToClose timeout (1.2 note)
- [ ] 3.8 Temporal replay check: workflow history replays deterministically (unit test with recorded history)
- [ ] 3.9 Equivalence gate: vulnerable-fastapi scan produces identical final findings to 1.2 baseline; wall-clock improved

## 4. Dead-code audit and deletion
> Audit already done (2026-09-29): the 60%-confidence vulture list (114 flags) is ~all false positives — `@field_validator`/`@model_validator` methods are pydantic-invoked; `*_activity` functions are registry-registered. Verified findings:

- [x] 4.1 Delete `run_fake_scan` (`run_scan.py:3023`) + its `__init__.py` re-export — only verified-dead symbol
- [ ] 4.2 DO-NOT-DELETE ledger (unwired contracts, keep): `KBContextProvenance` (KB-provenance wiring change pending), `RunRepo`/`RepoRole` (multi-repo-scanning spec), auth subdomain `AuthProfile/LoginStep/BrowserLoginStep/EnvProfile/CredentialProvider` (ADR-018/023 dormant), `TriageLabel/DeploymentIntent/ReVerificationOutcome/VerdictDefaults/FindingProvenance` (domain-model/provenance specs; §2.5 wires the raw-string bypasses instead)
- [ ] 4.3 `gapfill_pass` inert field: deferred decision (purge-or-wire) — out of scope for this change unless decomposition touches it
- [ ] 4.4 Unused-import sweep across `src/quarry_activities/` (537 at audit time) and other packages
- [ ] 4.5 Remove stale comments referencing deleted code
- [ ] 4.6 Suite green after deletions
- [ ] 4.7 Import-cycle root fix (one structural cause verified by audit): hoist shared leaf types (`PluginType`, `FindingSink`, `ToolSpec`) into `quarry` core so `models↔prompts`, `plugins↔integrations`, `plugins↔tools`, `plugins→activities` cycles collapse to one-way deps

## 5. `run_scan.py` decomposition (4307 LOC — grew from ~3989)
> Preconditions: §2.2 (round-resume) landed. Constraint: run_scan.py is the import hub — keep back-compat re-export shims (`:112-130`), migrate the 6 golden tests deliberately. Seam pattern proven: `coverage_loop.py`/`prove_stage.py`/`tracer_stage.py`/`dynamic_validate_stage.py` already extracted; `_RoundOutcome` NamedTuple accumulator convention is the interface.

- [ ] 5.1 Extract candidate-source/sweep wiring into its own module
- [ ] 5.2 Extract streaming dedup + validation pool (falls out of §3)
- [ ] 5.3 Extract coverage-ledger operations
- [ ] 5.4 Extract promotion wiring + event emission
- [ ] 5.5 Suite green after each extraction (no logic edits during pure moves)

## 6. Invariant consolidation
- [x] 6.1 Replace hand-counted activity-count literal — DONE in #51 (`discover_activities()` registry-derived)
- [x] 6.2 Audit other hand-counted literals — DONE: `workflows == 4` found; fix tracked as §2.4
- [ ] 6.3 Single inventory for prompt templates / panel config / profile defaults (document or module)

## 7. Guardrails
- [ ] 7.1 CI gate: dead-code check (`vulture` with allowlist for pydantic validators + `@activity.defn`, or pyright strict-unused) on changed files
- [ ] 7.2 Benchmark gate: standardized vulnerable-fastapi scan completes under target wall-clock with identical findings (target ≈ half of 1.2's ~90 min)

## 8. Landing
- [ ] 8.1 Conventional commit(s), push, CI green
- [ ] 8.2 `openspec archive codebase-cruft-purge --yes` (skip-specs change)
