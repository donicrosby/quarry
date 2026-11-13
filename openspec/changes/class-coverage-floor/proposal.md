# Change: class-coverage-floor

## Why

A requested vulnerability class that produces **zero candidates** currently terminates silently. The only backstop is the gapfill stage, which relies on a model *proposing* the gap as a free-form investigation — and in scan run `ebdafaba` (2026-09-15, vulnerable-fastapi, focus `[secrets, idor, command_injection, ssrf]`) the ssrf class received zero hunt candidates and gapfill never re-queued it, yielding a silent class miss on a known ground-truth sink.

Class coverage must be guaranteed by the workflow, not by a model roll. This is the same structural lesson as the secrets sweep and the degenerate-debater schema gate: no single model decision may decide whether a requested class was searched at all.

## What Changes

- After the final hunt round (including gapfill), the workflow computes per-requested-class candidate counts from the coverage ledger.
- Any requested class with **zero** candidates triggers a deterministic forced hunt pass for that class: a fresh hunt task scoped to the class with its prompt template, bounded rounds (configurable, default 1), tagged `forced_class_hunt` in provenance.
- The forced pass runs *before* validation begins, so its candidates flow through the normal validate/dedup/promotion pipeline.
- A `class_coverage_floor` event is recorded per forced class (class, round count, candidates produced) in the scan manifest.
- If the forced pass still yields zero candidates, the scan completes normally but the report marks the class `coverage: forced_hunt_exhausted` rather than silently absent.

## Impact

- **Specs**: `coverage-ledger-and-gapfill` (ADDED requirement), `hunt-stage` (ADDED requirement for forced pass semantics).
- **Code**: `src/quarry_workflows/run_scan.py` (post-hunt coverage check + forced spawn), possibly `src/quarry_activities/hunt.py` (class-scoped task constructor).
- **Provenance**: new event type `class_coverage_floor`; manifests grow one field.
- **Cost**: bounded — forced pass only fires on zero-candidate classes, default 1 round. Worst case adds one hunt round per missed class.
- **Non-goals**: per-class candidate *quality* (validation's job); classes not in the scan focus (only requested classes get the floor); deterministic sink sweeps (a complementary, per-class technique — this change is class-neutral).
