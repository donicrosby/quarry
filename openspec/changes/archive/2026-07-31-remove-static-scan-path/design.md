## Context

Reference-alignment roadmap, Phase 0. The target architecture is a fully agentic,
Shannon-shaped live pentester with Glasswing's iterative loops and MDASH's
multi-model panel (see Phase 1–3 changes). Quarry today is code-centric and already
close to Glasswing; the static analysis path is pre-pivot debt.

Audit findings this rests on:
- Only two files were ever deleted in 104 commits; the pivot *unwired* the static
  path but left it in the tree.
- `attack_surface.py`, `vuln_classes/idor.py`, `vuln_classes/command_injection.py`
  are unregistered in worker/server and have no caller, yet ~25 tests pass against
  them (false confidence).
- `validate-idor-candidate` / `validate-command-injection-candidate` are registered
  but never dispatched by `run_scan.py` — orphaned hand-coded validators.
- `scan_repo_for_secrets` IS still consumed by `diff_scan.py` — the one static
  scanner that stays.
- `CoverageLedger.attack_surface_items_scanned/_total` now count agentic tasks; the
  labels lie.

## Goals / Non-Goals

**Goals:**
- Delete the dead static path (producers, UI, API, table, tests).
- Remove the orphaned per-class dynamic validators so Phase 1 replaces them cleanly.
- Stop the report/ledger from lying about what it counts.
- Encode the "agentic-only candidate sourcing" invariant so the path can't creep back.

**Non-Goals:**
- No new agentic validation (Phase 1). No live exploitation (Phase 2). No panel work
  (Phase 3).
- No change to `scan_repo_for_secrets` or the diff-scan workflow.

## Decisions

### D1: Delete, don't deprecate

The static path has no consumers, so there is nothing to migrate. Deleting (rather
than marking deprecated) is what removes the false-confidence tests. The git history
preserves it if it is ever wanted back.

### D2: Keep `scan_repo_for_secrets`

It is live via `diff_scan.py`. Removing it would break commit-diff scanning. It stays
registered; only its role as a *main-pipeline candidate source* was already gone.

### D3: Rename rather than repurpose the coverage fields

`attack_surface_items_scanned/_total` → agentic-unit names (e.g.
`agent_tasks_scanned/_total`), `attack_surface_item_id` → a scope/task identifier.
Renaming is honest; repurposing-in-place (keeping the name) is what created the debt.
Old persisted rows lose these values (deserialize to defaults) — acceptable for a
local research tool with no migration guarantees; documented, not engineered around.

### D4: Drop the `attack_surface_items` table

New DBs simply won't create it. Existing local DBs keep an empty orphan table
harmlessly, or a one-line drop can be issued; no data migration since nothing reads it.

### D5: Capture the invariant as a spec

A `RunScanWorkflow`-level test asserts every candidate traces to a hunt task, so a
future static producer can't silently re-enter as a candidate source.

## Risks / Trade-offs

- **[Deleting tests looks like lost coverage]** → they only ever tested unreachable
  code; net test signal *improves* because the suite stops implying the static path
  works.
- **[A hidden consumer of a "dead" module]** → mitigate by grepping registrations and
  callers before each deletion (the audit already did this: zero callers), and by
  running the full suite after each removal.
- **[Schema field rename breaks a golden report fixture]** → expected; update the
  golden fixtures as part of the change.

## Migration Plan

- Purely subtractive plus field renames; no runtime migration for a local tool.
- Fresh `uv sync && task test` is the acceptance bar.
- Rollback: revert the change; git history retains all deleted modules.

## Open Questions

- Should the `attack_surface_items` table get an explicit `DROP TABLE IF EXISTS`
  migration, or is leaving an empty orphan table on old local DBs acceptable?
  (Recommendation: no migration; document it.)
- Do any golden fixtures beyond the attack-surface ones embed the old coverage field
  names? Resolve during apply by running the golden suite.
