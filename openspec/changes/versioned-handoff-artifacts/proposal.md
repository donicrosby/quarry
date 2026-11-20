# Proposal: versioned-handoff-artifacts

## Why

ADR-026 rule 6 mandates "Handoff over compaction for long tasks": when an agent's
context budget is exhausted, state SHALL transfer to a fresh instance through versioned
artifacts (ArchitectureDoc, coverage ledger, hunt handoff), not through conversation
summarisation alone. Today ArchitectureDoc lives only in the SQLite database
(b284af7:src/quarry_persistence/repositories.py:466) and the CoverageLedger is written
to disk without version stamps (b284af7:src/quarry_activities/coverage.py:258). No
HuntHandoff artifact exists. A fresh agent cannot cold-start from artifacts alone
because the artifacts carry no version, no round identity, and no handoff semantics.

## What Changes

1. **New `HuntHandoff` schema** — a structured artifact recording what was covered,
   what was found, what's next, and open hypotheses per scan round.
2. **Version stamps on handoff artifacts** — every ArchitectureDoc, CoverageLedger,
   and HuntHandoff SHALL carry a `scan_ordinal` (scan version) and `artifact_version`
   (monotonic counter within a scan), making them diffable between scans.
3. **ArchitectureDoc to artifact store** — ArchitectureDoc SHALL be persisted as a
   versioned artifact (new `ArtifactKind.ARCHITECTURE_DOC`) in addition to its DB
   record, so downstream agents can load it without SQLite access.
4. **CoverageLedger versioned** — the existing `write_coverage_artifact` path SHALL
   route through `LocalArtifactStore` and attach version stamps.
5. **Cold-start resume** — the scan workflow SHALL support resuming a killed hunt
   from the latest handoff artifacts alone, rehydrating ArchitectureDoc,
   CoverageLedger, and HuntHandoff from the artifact store without requiring the
   original workflow's in-memory state.

## Impact

- **Schemas**: new `HuntHandoff` class; `ArchitectureDoc` and `CoverageLedger` gain
  `scan_ordinal` and `artifact_version` fields; new `ArtifactKind.ARCHITECTURE_DOC`
  and `ArtifactKind.HUNT_HANDOFF` values.
- **Activities**: new `write_handoff_artifacts` activity (persists all three at end of
  HUNT stage); `build_coverage_ledger_activity` amended to use `LocalArtifactStore`
  and attach version stamps; recon synthesis amended to write ArchitectureDoc to
  artifact store.
- **Workflows**: `RunScanWorkflow` gains a `resume_from_artifacts` code path at HUNT
  entry that loads artifacts when resuming a previously-started hunt round.
- **Artifact store**: `LocalArtifactStore` surface gains no new methods; the version
  stamps live inside the payload schemas.
- **Non-goals**: This change does NOT implement compaction strategy changes, does NOT
  alter the Temporal event-history replay path, and does NOT add a git-diff backend
  for artifact comparison (the version stamps make that possible but it is
  out-of-scope).

## Ticket Reconciliation vs 2026-09-10 Body

The original ticket (t_bfef4c85, written 2026-09-10) assumed:
- `ArchitectureDoc` and `CoverageLedger` "exist" as handoff-ready artifacts — they
  exist as schemas but ArchitectureDoc is DB-only (not artifact-store-backed) and
  CoverageLedger's artifact write bypasses `LocalArtifactStore` with no version
  stamps. Both gaps are addressed here.
- A research doc at `docs/research/harness-engineering-research.md §4` — this file
  does not exist at b284af7. The binding reference is ADR-026 rule 6, which
  codifies the same principle. The research doc reference is DROPPED.
- "Test that kills a workflow mid-hunt and resumes" — this is an implementation
  acceptance criterion for the coder, not spec text. The scenario
  `cold_start_resume_from_artifacts` specifies the behaviour the test validates.
- "Artifacts must be diffable between scans" — version stamps (scan_ordinal +
  artifact_version) provide the diff key. A git-diff adapter is deferred to a
  follow-up.