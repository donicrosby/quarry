## Why

The week-12 pure-agentic pivot unwired the static analysis path from the workflow
but left the code, schemas, tables, TUI screens, API routes, and ~25 tests in the
tree. Those tests still pass, so a reader believes the static scanners work — but
nothing dispatches them. This is dead code masquerading as a feature, and it is the
single biggest source of false confidence in the repo. The project direction is a
**fully agentic pentest workhorse** (Shannon-shaped, per the reference systems), so
the static path is debt, not a parked capability.

This is Phase 0 of the reference-alignment roadmap: clear the ground before building
agentic dynamic validation (Phase 1) and live exploitation (Phase 2). It is
deliberately first because it is unblocked and it frees the `dynamic_validate` role
seat and the pipeline surface that later phases build on.

## What Changes

- **Remove** the orphaned static candidate producers and their tests:
  `quarry_activities/attack_surface.py` (FastAPI route extraction),
  `quarry_plugins/vuln_classes/idor.py`, `quarry_plugins/vuln_classes/command_injection.py`.
- **Remove** the two orphaned, hand-coded per-class dynamic validators
  (`validate-idor-candidate`, `validate-command-injection-candidate` in
  `dynamic_validation.py`) — they are registered but never dispatched, and Phase 1
  replaces them with an agentic validator. **BREAKING** for anyone importing them.
- **Remove** the orphaned static UI and API surface: `tui/screens/attack_surface.py`,
  `tui/widgets/route_table.py`, the `GET /scans/{id}/attack_surface` route, the
  `attack_surface_items` table, and the report's attack-surface block.
- **Keep** `scan_repo_for_secrets` — it is still consumed by `diff_scan.py` (the
  commit-diff feature), so it is live, not dead.
- **Rename** the misleading `CoverageLedger.attack_surface_items_scanned/_total` and
  `CoverageGap.attack_surface_item_id` fields to name what they now count (agentic
  tasks / scope units), and update the report template.
- Establish the invariant, in a spec, that candidate findings come only from agentic
  sources so the static path cannot silently return.

Non-goals: no new agentic capability (that is Phase 1+); no change to hunt, validate,
prove, tracer, or the coverage loop beyond the field rename.

## Capabilities

### New Capabilities
- `agentic-candidate-sourcing`: candidate findings are produced only by agentic
  activities (the hunt loop and its re-queue edges); the pipeline contains no static
  scanner or attack-surface enumeration stage, and coverage accounting names agentic
  units rather than attack-surface items.

### Modified Capabilities
<!-- The static path predates OpenSpec adoption and has no captured spec, so there is
     nothing to emit REMOVED deltas against; the removal is recorded as tasks plus the
     new invariant spec above. -->

## Impact

- **Code removed**: ~5 modules + orphaned API route + DB table + report block + ~25
  tests. Net reduction.
- **Schema**: `CoverageLedger` / `CoverageGap` field renames (a schema change; old
  persisted rows with the old names deserialize as defaults — acceptable for a local
  research tool, noted in design).
- **Persistence**: drop the `attack_surface_items` table (migration/no-op on fresh
  DBs; documented).
- **Registration**: remove the dead activities from `quarry_worker/main.py` and
  `quarry_server/app.py` (dual-worker rule).
- **Unblocks**: Phase 1 (`agentic-dynamic-validation`) reuses the freed
  `dynamic_validate` seat and validator dispatch point.
