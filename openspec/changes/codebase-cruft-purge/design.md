# Design: SPEC-D1 + ADR-D3 — stage persistence + round-scoped resume

Change: `codebase-cruft-purge` §2.1 + §2.2. Owning worktree:
`/opt/data/workspace/quarry-wt-cruft1` (branch `fix/cruft-stage-persistence`).

## Problem (verified facts)

1. **SPEC-D1**: three canonical stages never durably checkpointed:
   VALIDATION, GAPFILL, COVERAGE have no `_persist_scan_stage` call and no
   `_stage_completed` resume gates. Violates scan-orchestration spec
   "State is persisted before advancing".
2. **ADR-D3**: resume works only for round 0. `coverage_round_index` is
   written every round (`run_scan.py:788`) but never read; gapfill/feedback
   re-queue tasks are never persisted (`save_agent_task` is a documented
   no-op in `quarry_activities/repo.py`); `hunted_cells`,
   `needs_proof_findings`, `hunter_gaps`, `proof_artifacts`,
   `traced_finding_ids`, `all_agent_tasks` are workflow-local. A crash in
   round ≥ 1 loses the task queue.

## Scope decision (2.1)

**Persist the three missing stages; do NOT fold VALIDATION out of
`COMPLETED_STAGE_ORDER`.** Rationale: the workflow already sets
`self._current_stage = "VALIDATION"` and tests pin the order
(`test_workflow.py:44-45`, integration fixtures use `"VALIDATION"` metadata);
folding it would churn the stage vocabulary and every pinned test to save one
persist call. Cheap path: add the three `_persist_scan_stage` calls +
`_stage_completed` gates mirroring the existing per-stage pattern.

- VALIDATION gate: the deterministic secrets gate runs inside HUNT (existing
  behavior); a `VALIDATION` completion marker therefore just records "hunt's
  validation sub-work finished" — the HUNT gate already covers re-entry
  safety. Persist after the hunt block completes (`:1657` already persists
  HUNT; add VALIDATION right after the secrets-gate block).
- GAPFILL gate: persist after the gapfill-coverage emission completes in the
  loop-bottom (post `gapfill.completed` event).
- COVERAGE gate: persist right after `_record_coverage` returns
  (`run_scan.py:981-995` region), before REPORT.

## Scope decision (2.2) — minimal round-resume contract

Goal: **round > 0 crash does not restart the scan from scratch, does not
duplicate findings, and is deterministic on replay.** Not in scope: resuming
*mid-stage* inside a round (stage-level gates already cover round 0 only;
extending gates per-round would touch every stage block).

### Persisted state (new)

1. **Agent-task persistence (real, replacing the no-op)**:
   `save_agent_task` upserts an `AgentTaskRecord` (merge on `(scan_id, id)`,
   same pattern as `save_candidate_finding`); `load_agent_tasks` returns all
   persisted tasks for the scan ordered by (round_index, id). The workflow
   persists: every recon-derived task before round 0 (already attempted —
   currently a no-op), every gapfill/feedback `next_tasks` at loop bottom
   (after `dedup_new_tasks`, before rebinding `round_tasks`).
2. **Round cursor**: reuse the existing `coverage_round_index` metadata write
   (`:788`) but make it the *resume source*: on resume, read
   `coverage_round_index`; the loop starts at `max(0, persisted_round + 1)`.
   Also persist `coverage_loop_stop_reason` in metadata at loop exit (when
   `stop_reason` fires) so a post-loop resume skips the loop entirely.
3. **Accumulator reload on resume**: on any resume (`completed_stage is not
   None`), reload from DB (all merge-idempotent): `candidate_findings` /
   `final_findings` (existing `_load_*` helpers), `needs_proof_findings`
   (candidates with `verdict == needs_proof` / no final verdict), traces via
   existing `load_traces` (rebuild `traced_finding_ids`), proof artifacts
   from candidate metadata or a new `save_proof_artifact` op. `hunter_gaps`
   and `hunted_cells` are re-derivable: `hunted_cells` from loaded
   `all_agent_tasks` via `cell_key`; `hunter_gaps` — persist alongside tasks
   as `AgentTask` with `source="gapfill"`... **simplification**: recompute
   `hunter_gaps = []` on resume (they only seed gapfill; gapfill re-runs from
   the ledger each round anyway). Acceptable because gapfill emission is
   idempotent against `hunted_cells`.

### Determinism notes

- All new state flows through `persist-scan-state` activities (already
  merge-idempotent); workflow reads only via load ops → replay-safe (state
  comes from activity results, not wall-clock).
- Round cursor via `workflow.now()`-free metadata round-trip; no new
  non-deterministic inputs.
- Event ordering: `round.started` per round unchanged; a resumed scan's event
  stream shows the already-emitted rounds (persisted from the prior life) and
  continues from the cursor — consumers must tolerate that (1.4 audit task
  covers consumers).

### Test contract

- Unit (workflow-level, `WorkflowEnvironment` seam like
  `test_workflow_concurrency.py`): kill the workflow after round 0 completes
  (fail the TRACER activity of round 1), resume, assert: loop resumes at
  round 1 cursor, gapfill/feedback tasks reloaded (not re-derived), no
  duplicate candidates/finals vs the pre-crash DB.
- Unit (persistence): `save_agent_task`/`load_agent_tasks` round-trip +
  merge-idempotency; round-cursor metadata round-trip.
- Integration (`test_resume.py`): existing round-0 resume tests stay green.

## Non-goals

- Mid-stage (intra-HUNT) resume within round > 0.
- Persisting `hunter_gaps` (recompute-empty; gapfill re-derives).
- Changing `COMPLETED_STAGE_ORDER` vocabulary.
