# Tasks: versioned-handoff-artifacts

## 1. Schema changes (pure data, no behaviour change)

- [ ] 1.1 Add `HuntHandoff` Pydantic model to `src/quarry/schemas.py` with fields:
  `id`, `scan_id`, `workspace_id`, `round_number`, `stage` (literal `"HUNT"`),
  `covered_scope_units`, `candidate_finding_ids`, `pending_task_count`,
  `open_hypotheses`, `scan_ordinal`, `artifact_version`, `created_at`.
  Use `ConfigDict(frozen=True)`. Add `_empty_*` factory helpers per existing
  convention.
  - [ ] Verify: `uv run python -c "from quarry.schemas import HuntHandoff; print(HuntHandoff.model_json_schema())"` exits 0.

- [ ] 1.2 Add `scan_ordinal: int` and `artifact_version: int` fields to
  `ArchitectureDoc` and `CoverageLedger`, defaulting to `1` so existing
  serialised records remain valid.
  - [ ] Verify: unit test confirms `ArchitectureDoc(..., scan_ordinal=1, artifact_version=1)` round-trips through `model_dump_json` + `model_validate_json`.

- [ ] 1.3 Add `ARCHITECTURE_DOC = "architecture_doc"` and
  `HUNT_HANDOFF = "hunt_handoff"` to `ArtifactKind` enum.
  - [ ] Verify: `ArtifactKind.ARCHITECTURE_DOC` and `ArtifactKind.HUNT_HANDOFF` resolve.

## 2. CoverageLedger routed through LocalArtifactStore

- [ ] 2.1 Replace the direct `ledger_path.write_bytes(data)` in
  `write_coverage_artifact` (`src/quarry_activities/coverage.py:258`) with a
  call to `LocalArtifactStore.put_json`. Pass `scan_ordinal` and
  `artifact_version` from the ledger.
  - [ ] Verify: existing coverage unit tests (`tests/unit/test_coverage*.py`) pass.

## 3. ArchitectureDoc to artifact store

- [ ] 3.1 In recon synthesis (`src/quarry_activities/recon_synthesis.py`), after
  building the ArchitectureDoc, persist it via `LocalArtifactStore.put_json` and
  return the `ArtifactRef` in the synthesis output.
  - [ ] Verify: recon integration test confirms artifact file exists on disk after
    synthesis.

- [ ] 3.2 Add `architecture_doc_artifact_ref: ArtifactRef | None` to
  `ReconSynthesisOutput` (or equivalent activity output schema).
  - [ ] Verify: `uv run pyright` clean on the amended activity and its caller.

## 4. HuntHandoff production activity

- [ ] 4.1 Create `write_handoff_artifacts` activity in a new or existing activity
  module (`src/quarry_activities/handoff.py`). It receives scan state (scan_id,
  workspace_id, round_number, covered units, existing findings, pending tasks,
  open hypotheses), builds three versioned artifacts, and persists each via
  `LocalArtifactStore.put_json`.
  - [ ] Verify: unit test writes all three artifacts and confirms they appear on
    disk with correct `ArtifactKind`.

- [ ] 4.2 Wire `write_handoff_artifacts` into `RunScanWorkflow` at the end of each
  HUNT stage pass, after hunters complete but before advancing to the next stage.
  - [ ] Verify: integration test confirms `HuntHandoff` artifact exists after a
    scan completes HUNT.

## 5. Cold-start resume in RunScanWorkflow

- [ ] 5.1 At HUNT stage entry, check for existing handoff artifacts in the
  artifact store. If `HuntHandoff` exists and the scan is a resume (not a fresh
  start), load ArchitectureDoc, CoverageLedger, and HuntHandoff; compute the
  set of already-covered scope units; emit only pending tasks.
  - [ ] Verify: integration test kills a scan during HUNT, resumes it, and
    confirms no duplicate hunter tasks are emitted.

- [ ] 5.2 Emit a `hunt.resumed_from_artifacts` workflow event when cold-start
  resume is triggered, carrying the `artifact_version` and `scan_ordinal` of the
  artifacts used.
  - [ ] Verify: event appears in scan event stream after resume.

## 6. Integration and regression gates

- [ ] 6.1 Add an integration test (`tests/integration/test_cold_start_resume.py`)
  that starts a scan, cancels it during HUNT, and resumes it from artifacts,
  asserting no duplicate findings and that covered units are not re-hunted.
  - [ ] Verify: `uv run pytest tests/integration/test_cold_start_resume.py -v` green.

- [ ] 6.2 Run the full CI-equivalent gate battery:
  `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`,
  `uv run pytest -x -q`. Confirm zero regressions against the ~1850-test suite.
  - [ ] Verify: all gates green, `openspec validate versioned-handoff-artifacts --strict` exit 0.

## 7. OpenSpec validation

- [ ] 7.1 `npx openspec validate versioned-handoff-artifacts --strict` — clean exit.
  - [ ] Verify: exit code 0, summary "Change 'versioned-handoff-artifacts' is valid."

## Notes

- The `scan_ordinal` counter is scoped to the target; `artifact_version` is scoped
  to (scan, artifact_type). Both start at 1. The implementation chooses where to
  source these counters (scan metadata, workflow state, or a DB sequence).
- Existing `CoverageLedger` records without `scan_ordinal`/`artifact_version`
  fields deserialise fine because Pydantic ignores extra fields on read and the
  new fields default to 1.
- Rejected from scope: git-diff adapter for artifact comparison (version stamps
  make this possible but it is deferred to a follow-up change).