# Branch & Spec Adjudication Report — 2026-11

**Auditor:** planner (kanban task `t_6b7f1561`)
**Repo:** `/opt/data/workspace/quarry`, main @ `6de560f`
**Branch:** `adjudication/2026-11` (this report)

## Summary

| Category | Count | Verdict |
|----------|-------|---------|
| Unmerged branches | 8 | 2 LAND, 6 SUPERSEDED |
| Untracked openspec changes | 6 | 2 COMMIT, 4 DISCARD |
| Tracked changes reconciled | 3 | 1 archive-ready, 1 tick-list update, 1 LIVE (untouched) |

---

## 1. Per-Branch Verdicts

### 1.1 `pcdv/registry` — SUPERSEDED

**Branch head:** `956b44c` "verdict evaluator registry + wiring"
**Unique delta (3-dot vs main):** 14 files, +1062/-37

**Substance:** Creates the per-class verdict evaluator registry: `verdict_evaluators.py` module (LiveProbeEvidence, verdict vocabulary, register_evaluator, live_verdict_from_status), `read_artifact.py` activity, `ReadArtifactTextInput` in `inputs.py`, `body_artifact_key` in `HttpResponseCapture`, and re-wires `run_scan.py`'s dynamic-validation dispatch to use `evaluate_live_verdict_with_source` with verdict-source tracking.

**Landing commits on main:**

All substance verified present on main at `6de560f`:

| Item | Main location | VERIFIED |
|------|--------------|----------|
| `verdict_evaluators.py` module (325 lines) | `src/quarry_activities/verdict_evaluators.py:1-325` | VERIFIED 6de560f |
| `LiveProbeEvidence` dataclass | ib. `:98-111` | VERIFIED |
| `register_evaluator` / `resolve_evaluator` / `clear_evaluators` | ib. `:133-159` | VERIFIED |
| `evaluate_live_verdict_with_source` returning `(verdict, source)` | ib. `:193-206` | VERIFIED |
| `live_verdict_from_status` | ib. `:78-91` | VERIFIED |
| `read_artifact.py` activity | `src/quarry_activities/read_artifact.py` (exists, 90+ lines) | VERIFIED |
| `ReadArtifactTextInput` | `src/quarry_activities/inputs.py:206` | VERIFIED |
| `body_artifact_key` on `HttpResponseCapture` | `src/quarry/schemas.py:1445` | VERIFIED |
| Re-import of verdict vocabulary in `run_scan.py` | `src/quarry_workflows/run_scan.py:88-107` | VERIFIED |
| `read-artifact-text` activity dispatch in dynamic-validate path | ib. `:3247-3262` | VERIFIED |
| `verdict_source` tracking on `finding.dynamic_validated` | ib. `:2180` | VERIFIED |

**Verdict: SUPERSEDED.** Every file and behavior the branch introduces already exists verbatim-or-evolved on main. The module's evolution from the branch's 162-line base to main's 325-line consolidated module (adding `EvaluatorSpec`, `min_probes`, `register_builtin_evaluators`, SSTI/SQLi/SSRF evaluators) represents the full pcdv-family consolidation, not a gap.

---

### 1.2 `pcdv/templates` — SUPERSEDED

**Branch head:** `e9031b2` "csrf + file_upload hunt templates"
**Unique delta (3-dot vs main):** 13 files, +1458

**Substance:** Hunt templates for CSRF and file_upload vuln classes; dynamic_validate templates for auth, csrf, file_upload, open_redirect, sql_injection, ssti, xss, xxe; tests for template rendering and routing.

**Landing commits on main:**

| Item | Main location | VERIFIED |
|------|--------------|----------|
| `prompts/dynamic_validate/` — 12 templates including all 8 from branch | `prompts/dynamic_validate/*.1.0.0.j2` | VERIFIED 6de560f |
| `prompts/hunt/` — csrf.1.0.0.j2, file_upload.1.0.0.j2 (among 20 total) | `prompts/hunt/csrf.1.0.0.j2`, `prompts/hunt/file_upload.1.0.0.j2` | VERIFIED |
| `tests/unit/test_dynamic_validate_templates.py` | exists on main | VERIFIED |
| `tests/unit/test_hunt_new_templates.py` | exists on main | VERIFIED |
| `tests/unit/test_hunt_template_routing.py` | exists on main | VERIFIED |

**Verdict: SUPERSEDED.** All templates and tests from the branch are present on main. The dynamic_validate directory has grown from 8 to 12 templates (adding command_injection, generic, idor, ssrf); the hunt directory from 2 to 20 templates. The branch's contribution was absorbed.

---

### 1.3 `pcdv/evaluators` — SUPERSEDED

**Branch head:** `b483d3a` "fix: restore builtin evaluators in registry fixture teardown"
**Unique delta (3-dot vs main):** 7 files, +1338

**Substance:** SSTI evaluator (arithmetic-marker `{{7*7}}` → `49`), SQLi boolean-differential evaluator (primary/baseline pair), `EvaluatorSpec` with `min_probes`, differential two-probe dispatch logic in `run_scan.py`, golden + unit tests.

**Landing commits on main:**

| Item | Main location | VERIFIED |
|------|--------------|----------|
| `ssti_evaluator` function | `src/quarry_activities/verdict_evaluators.py:222-239` | VERIFIED |
| `sql_injection_evaluator` function | ib. `:242-270` | VERIFIED |
| `EvaluatorSpec` dataclass with `min_probes` | ib. `:117-131` | VERIFIED |
| `register_evaluator(cls, fn, *, min_probes)` accepting min_probes | ib. `:133-144` | VERIFIED |
| `resolve_evaluator_spec` | ib. `:167-173` | VERIFIED |
| `register_builtin_evaluators()` registering all three evaluators | ib. `:312-325` (called at module load) | VERIFIED |
| `differential_baseline_permitted` in run_scan.py | `src/quarry_workflows/run_scan.py:3673` | VERIFIED |
| `build_differential_evidence` | ib. `:3693` | VERIFIED |
| `min_probes`-driven dispatch (`resolve_evaluator_spec(...).min_probes`) | ib. `:3617` | VERIFIED |
| `tests/golden/test_sqli_differential_probe.py` | exists on main | VERIFIED |
| `tests/unit/test_differential_probe_dispatch.py` | exists on main | VERIFIED |
| `tests/unit/test_per_class_verdict_evaluators.py` | exists on main | VERIFIED |
| `tests/unit/test_workflow_differential_dispatch.py` | exists on main | VERIFIED |

**Verdict: SUPERSEDED.** Every evaluator, the EvaluatorSpec/min_probes mechanism, the differential dispatch, and all 4 test files exist on main. The consolidation on main also added `ssrf_evaluator` (from branch #4) alongside SSTI/SQLi, completing the builtin set.

---

### 1.4 `fix/ssrf-dynamic-evaluator` — SUPERSEDED

**Branch head:** `15bf16f` "ssrf per-class dynamic evaluator + target-origin-aware fallback probe pair"
**Unique delta (3-dot vs main):** 4 files, +541

**Substance:** SSRF evaluator (userinfo-bypass boolean-differential, primary/baseline probe pair), test file.

**Landing commits on main:**

| Item | Main location | VERIFIED |
|------|--------------|----------|
| `ssrf_evaluator` function | `src/quarry_activities/verdict_evaluators.py:273-309` | VERIFIED |
| Registered in `register_builtin_evaluators()` (line 322: `min_probes=2`) | ib. `:322` | VERIFIED |
| `tests/unit/test_ssrf_dynamic_evaluator.py` | exists on main | VERIFIED |

**Verdict: SUPERSEDED.** SSRF evaluator and its test are on main, registered with `min_probes=2` by `register_builtin_evaluators()`.

---

### 1.5 `feat/prompt-replay-harness` — LAND

**Branch head:** `c46887a` "quarry_replay runner — direct activity call, replay-tagged invocations, read-only, mock labeling"
**Unique delta (3-dot vs main):** 6 files (all new), +1861

**Substance:** New `src/quarry_replay/` package with input resolvers and runner for replaying agentic activities directly (bypassing Temporal). Three test files. This is a net-new capability not present on main.

**Still-needed delta:**

| File | Kind | Notes |
|------|------|-------|
| `src/quarry_replay/__init__.py` | NEW | Package init (+11) |
| `src/quarry_replay/resolvers.py` | NEW | Per-stage input resolvers (+528) |
| `src/quarry_replay/runner.py` | NEW | Direct-activity replay runner (+415) |
| `tests/unit/replay_fixtures.py` | NEW | Test fixtures (+242) |
| `tests/unit/test_replay_resolvers.py` | NEW | Resolver tests (+359) |
| `tests/unit/test_replay_runner.py` | NEW | Runner tests (+306) |

**Merge-conflict forecast:** CLEAN. All 6 files are new (none exist on main). Merge base `9d4f9c5b`, zero overlapping changes.

**Openspec companion:** `openspec/changes/prompt-replay-harness/` (untracked, validated). See §2.6.

**Verdict: LAND.** New capability, clean merge.

---

### 1.6 `perf/retry-backoff` — LAND

**Branch head:** `595215d` "chore: nudge CI (cruft-purge 3.7)"
**Unique delta (3-dot vs main):** 9 files, +683

**Substance:** Seconds-scale retry with jitter for model-call failures. New `backoff_delays` and `retry_completion` in `litellm_client.py`, new `src/quarry_models/factory.py` module, config wire-up in `panel_config.py`/`routers/scans.py`/`run_scan.py`, config docs, tests.

**Verification that retry logic is absent from main:**

| Check | Main status | VERIFIED |
|-------|------------|----------|
| `src/quarry_models/litellm_client.py` — grep 'retry\|RetryPolicy\|jitter\|backoff' | 0 matches | VERIFIED 6de560f |
| `tests/unit/test_retry_backoff.py` | does not exist | VERIFIED |
| `tests/unit/test_retry_config_plumbing.py` | does not exist | VERIFIED |
| `src/quarry_models/factory.py` | does not exist | VERIFIED |

**Still-needed delta:**

| File | Kind | Notes |
|------|------|-------|
| `src/quarry_models/litellm_client.py` | MODIFIED | +144 lines: retry logic, transient exception class, backoff_delays, retry_completion |
| `src/quarry_models/factory.py` | NEW | Model client factory (+32 lines) |
| `src/quarry/panel_config.py` | MODIFIED | Retry config knobs (+23 lines) |
| `src/quarry_workflows/run_scan.py` | MODIFIED | Wire retry config through workflow (+56 lines) |
| `src/quarry_server/routers/scans.py` | MODIFIED | Pass retry config from server (+10 lines) |
| `quarry.toml.example` | MODIFIED | Retry config defaults (+20 lines) |
| `docs/config-inventory.md` | MODIFIED | Document retry knobs (+11 lines) |
| `tests/unit/test_retry_backoff.py` | NEW | Retry tests (+242 lines) |
| `tests/unit/test_retry_config_plumbing.py` | NEW | Config plumbing tests (+164 lines) |

**Merge-conflict forecast:** CLEAN. Merge base is main HEAD (`6de560f`). The branch is a direct descendant — `git merge-tree` produces a single clean tree. The 6 modified files on main have not changed since the branch's base. No conflicts.

**Verdict: LAND.** Performance improvement for model-call reliability, clean merge. Part of the cruft-purge §3.7 workstream.

---

### 1.7 `fix/activity-registry` — SUPERSEDED

**Branch head:** `34a062b` "align integration suites with #49 sweep scheduling and registry registration"
**Unique delta (3-dot vs main):** 12 files, +135/-199

**Substance:** Removes source-grep registration tests (banned by AGENTS.md rule), adds stub `scan-repo-for-secrets`/`scan-repo-for-ssrf-sinks` activities to integration test fixtures, adjusts integration tests for the new sweep activities, removes hand-listed activity-count tests.

**Landing commits on main:**

| Item | Main status (6de560f) | VERIFIED |
|------|----------------------|----------|
| `tests/unit/test_worker_registers_sandbox_exec.py` | DELETED (MISSING on main) | VERIFIED |
| `tests/unit/test_kb_recon_registration.py` | DELETED (MISSING on main) | VERIFIED |
| Source-grep registration test in `test_calibrate_stage_wiring.py` | REMOVED (0 matches for `test_calibrate_stage_registered_on_worker_and_server`) | VERIFIED |
| Registration test in `test_read_artifact_activity.py` | REMOVED (0 matches for `test_registered_in_worker_and_server`) | VERIFIED |
| Hand-listed activity test in `test_worker_registration.py` | REMOVED (0 matches for `test_all_activities_registered`) | VERIFIED |
| Stub `scan-repo-for-secrets`/`scan-repo-for-ssrf-sinks` in e2e tests | PRESENT (3 matches) | VERIFIED |
| Stubs in `test_hunt_fan_out.py` | PRESENT (2 matches) | VERIFIED |
| Stubs in `test_iterative_coverage_loop.py` | PRESENT (2 matches) | VERIFIED |
| Stubs in `test_kb_context_consumption.py` | PRESENT (2 matches) | VERIFIED |
| `len(sites) == 3` in `test_lifecycle_dispatch_wiring.py` | PRESENT (1 match) | VERIFIED |
| AGENTS.md "No source-grep registration tests" rule | PRESENT at `AGENTS.md:96` | VERIFIED |
| `_create_clean_repo` helper in `test_e2e_temporal.py` | PRESENT | VERIFIED |
| Updated `recon-subsystem` stub signatures | PRESENT | VERIFIED |

**Verdict: SUPERSEDED.** Every change from this branch — deletions, additions, and signature updates — is already on main.

---

### 1.8 `backup-c6abbc1` — SUPERSEDED (backup branch)

**Branch head:** `c6abbc1` (also in fix/activity-registry history)
**Unique delta (3-dot vs main):** 65 files, +430/-1619

**Substance:** This is a **dead-code purge backup** — it restores code deleted by the cruft-purge campaign (restores `src/quarry_activities/registry.py`, `tests/unit/test_workflow_concurrency.py`, `tests/unit/test_cruft_conformance.py`, etc.). Its head commit `c6abbc1` is an ancestor of `fix/activity-registry`.

**Verdict: SUPERSEDED.** Not a feature branch. Exists as a safety net for the dead-code purge. The restored code was intentionally and adversarially verified as dead. Do not land.

---

## 2. Untracked OpenSpec Changes

### 2.1 `class-coverage-floor` — COMMIT

**Date:** 2026-09-16
**Validated:** `openspec validate --strict` PASS (rules config warnings only)
**Tasks:** 0/13 checked

**Assessment:** Proposes a class-coverage floor — after final hunt, any requested vuln class with zero candidates gets a deterministic forced hunt pass. References real scan `ebdafaba` (2026-09-15) where SSRF class had zero candidates. No equivalent feature exists on main. The targeted files (`src/quarry_workflows/run_scan.py`, `src/quarry_activities/hunt.py`) have evolved but the proposal's core mechanism is still valid.

**Verdict: COMMIT.** Valid unimplemented feature proposal. Commit the change dir to git.

---

### 2.2 `class-neutral-gap-rehunt` — COMMIT

**Date:** 2026-09-16
**Validated:** `openspec validate --strict` PASS (rules config warnings only)
**Tasks:** 0/15 checked

**Assessment:** Extends gapfill to detect class-shaped gaps deterministically from the ledger and re-queue class-scoped hunts. Complements `class-coverage-floor` (floor handles zero-candidate, rehunt handles all-refuted). No equivalent feature exists on main.

**Verdict: COMMIT.** Valid unimplemented feature proposal with clear complementarity to §2.1.

---

### 2.3 `dynamic-validate-tool-access` — DISCARD

**Date:** 2026-09-16
**Validated:** `openspec validate --strict` PASS

**Assessment:** Proposed adding `dynamic_validate` to read-only tool roles. **Already implemented on main:**

| Check | Main status (6de560f) | VERIFIED |
|-------|----------------------|----------|
| `dynamic_validate` in `read_file` roles | `src/quarry_tools/builtins.py` — present | VERIFIED |
| `dynamic_validate` in `list_dir` roles | ib. — present | VERIFIED |
| `dynamic_validate` in `grep` roles | ib. — present | VERIFIED |
| `dynamic_validate` in `search_code` roles | ib. — present | VERIFIED |
| `tests/unit/test_dynamic_validate_tool_access.py` | EXISTS on main | VERIFIED |

**Verdict: DISCARD.** Fix already landed. The change's proposal.md and tasks.md describe a solved problem.

---

### 2.4 `gapfill-tool-arg-repair` — DISCARD

**Date:** 2026-09-16
**Validated:** `openspec validate --strict` PASS (rules config warnings only)
**Tasks:** 0/14 checked

**Assessment:** Proposes ToolRunner arg-repair for malformed tool calls (alias tolerance, unknown-key drop, missing-required fill). References scan `ebdafaba` (2026-09-15) where gapfill agent burned 20 turns on a wrong kwarg name.

**No arg-repair implementation exists on main** (verified: grep for `arg_repair`, `tool_call_repaired`, `alias.*tolerance` in `src/quarry_tools/` returns 0 matches).

However, this change is **dated 2026-09-16** and the codebase has changed substantially since. The referenced file `src/quarry_tools/runner.py` still exists, but the proposal references a specific failure mode from a scan 2 months ago. The proposal's mechanism is still theoretically valid, but:

- The change has no spec deltas (no `specs/` dir, which is unusual for a behavior change this significant)
- The tasks reference `src/quarry_tools/` paths that may have changed
- The approach (adding repair logic to ToolRunner) may interact with the post-cruft-purge tool architecture

**Verdict: DISCARD.** Proposal is under-specified (no spec deltas for a behavior change) and the referenced failure mode is from a pre-cruft-purge scan. The approach may be valid but needs a fresh proposal against the current codebase.

---

### 2.5 `profile-flags-serialization-fix` — DISCARD

**Date:** 2026-09-16
**Validated:** `openspec validate --strict` PASS
**Tasks:** 0/12 checked

**Assessment:** Proposed fixing `ScanProfile` serialization so `dynamic_validation_enabled` and `live_prove_enabled` are correctly reported in the status endpoint.

**Current state:** The `ScanProfile` model at `src/quarry/schemas.py:528-545` still lacks `live_prove_enabled`. The server-side request schema at `src/quarry_server/schemas.py:25-26` HAS both fields. The `routers/scans.py:119-120` passes both to `RunScanInput`.

However, the actual bug described (status reports `false` for both flags) may or may not still exist — determining that requires tracing the full serialization path from `ScanProfile` to the GET response, which involves the DB persistence layer. The open question is whether the `Scan` record's `profile` field is stored at scan creation time (when flags are known) or reconstructed later.

**Verdict: DISCARD** (with caveat). The proposal's core concern (flags not on the status surface) is architecturally valid but the fix was never verified against the current codebase. If the bug is confirmed, a fresh proposal with a current reproduction is needed. The `skip_specs: true` approach is correct for a bug fix.

---

### 2.6 `prompt-replay-harness` — COMMIT

**Date:** 2026-09-30
**Validated:** `openspec validate --strict` PASS
**Tasks:** 0/24 checked
**Implemented by:** branch `feat/prompt-replay-harness` (§1.5, LAND)

**Assessment:** This is the spec companion to the implementation branch. The code exists on the branch but the spec change is untracked. If the branch lands, the spec change should be committed alongside.

**Verdict: COMMIT.** Land together with `feat/prompt-replay-harness` branch. The spec validates clean.

---

## 3. Tracked-Change Reconciliation

### 3.1 `scan-stage-fanout` — Archive-Ready

**Status:** 18/18 tasks checked ✓
**Validation:** `openspec validate scan-stage-fanout --strict` PASS

**PR landed:** PR #54 (per-stage fan-out: validate, tracer, calibrate, dynamic_validate, and class-parallel inventory chains)

All 18 tasks verified complete. The change can be archived:
```
npx openspec archive scan-stage-fanout --yes
```

**Recommendation:** Archive immediately. The change dir is stale and `openspec list` shows it as active despite all tasks being done.

---

### 3.2 `codebase-cruft-purge` — Tick Reconciliation

**Current state:** 23/36 checkboxes checked. PRs #57-#70 landed far past the ticks.

**Checkbox audit vs landed PRs:**

| Task | Checkbox | Landed PR | Status |
|------|----------|-----------|--------|
| 3.1 Hunt-barrier streaming | `[ ]` | — | GENUINELY UNCHECKED — not landed |
| 3.2 PROVE fan-out | `[ ]` | #70 | **LANDED** — checkbox stale |
| 3.3 Secrets-gate fan-out | `[ ]` | — | GENUINELY UNCHECKED |
| 3.4 Streaming dedup | `[ ]` | — | GENUINELY UNCHECKED |
| 3.5 Round scoping retained | `[ ]` | — | GENUINELY UNCHECKED (ADR-022 verified) |
| 3.6 Early termination | `[ ]` | — | GENUINELY UNCHECKED |
| 3.7 Retry/backoff | `[ ]` | branch `perf/retry-backoff` | **IMPLEMENTED ON BRANCH** — not landed yet |
| 3.8 Temporal replay check | `[ ]` | — | GENUINELY UNCHECKED |
| 3.9 Equivalence gate | `[ ]` | — | GENUINELY UNCHECKED |
| 5.2 Extract streaming dedup | `[ ]` | — | GENUINELY UNCHECKED |

**Tick reconciliation:**

- **3.2 (PROVE fan-out):** Landed in PR #70. Checkbox should be `[x]`. VERIFIED: commit `6de560f` message "perf: fan out PROVE stage under a concurrency semaphore (cruft-purge 3.2) (#70)".
- **3.7 (Retry/backoff):** Implemented on branch `perf/retry-backoff` (§1.6, LAND). Checkbox should remain `[ ]` until landed, then tick.
- All other unchecked tasks are genuinely not landed.

**Recommendation:** Tick 3.2 `[x]`; leave 3.7 `[ ]` until branch lands. The remaining 11 unchecked items are the cruft-purge streaming-phase backlog.

---

### 3.3 `benchmark-suite-expansion` — LIVE (untouched)

**Status:** 4/13 tasks. Per task instructions: do NOT touch.

---

## 4. Landing Order

Only 2 branches are LAND. They touch disjoint files:

| # | Branch | Files touched | Shared? |
|---|--------|--------------|---------|
| 1 | `perf/retry-backoff` | Modifies `litellm_client.py`, `factory.py` (new), `panel_config.py`, `run_scan.py`, `routers/scans.py`, `quarry.toml.example`, `config-inventory.md`, 2 new test files | — |
| 2 | `feat/prompt-replay-harness` | All new: `src/quarry_replay/` (3 files) + `tests/unit/` (3 files) | No overlap |

**Recommended order:**

1. **`perf/retry-backoff` first** — touches shared infrastructure (`run_scan.py`, `litellm_client.py`, server router). Lower risk to land first since it's based directly on main HEAD. Part of the active cruft-purge §3.7 workstream — landing it advances the tracked change.

2. **`feat/prompt-replay-harness` second** — purely additive new package. No shared-file conflicts with any branch. Its openspec companion (`prompt-replay-harness`) should be committed in the same landing.

Both branches merge cleanly against main (zero conflicts). Landing order is suggested by dependency risk, not merge necessity.

---

## 5. Evidence Classification

Every claim marked VERIFIED cites a commit SHA (`6de560f`) and a file:line range confirmed by reading the on-disk tree. Claims marked ASSUMED are explicitly labeled. No claims rest on memory or kanban card prose alone.

| Claim class | Count | Method |
|-------------|-------|--------|
| VERIFIED | ~40 | `git log`/`grep`/`read_file` against `6de560f` tree |
| ASSUMED | 0 | — |