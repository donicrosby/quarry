## 1. Confirm no live consumers (safety gate)

- [x] 1.1 Re-grep for callers/registrations of each removal target (`attack_surface`, static `idor`, static `command_injection`, `validate-idor-candidate`, `validate-command-injection-candidate`) across `src/` and confirm zero dispatch sites in `run_scan.py` and zero registrations that are actually reached.
- [x] 1.2 Confirm `scan_repo_for_secrets` IS still referenced by `diff_scan.py` (it must survive).

## 2. Remove static candidate producers

- [x] 2.1 Delete `src/quarry_activities/attack_surface.py` and `tests/unit/test_fastapi_route_extractor.py`, `tests/golden/test_attack_surface.py`, and the attack-surface fixtures.
- [x] 2.2 Delete `src/quarry_plugins/vuln_classes/idor.py` and `tests/unit/test_idor_scanner.py`.
- [x] 2.3 Delete `src/quarry_plugins/vuln_classes/command_injection.py` and `tests/unit/test_command_injection_scanner.py`.
- [x] 2.4 Remove the orphaned per-class dynamic validators (`validate_idor_candidate_activity`, `validate_command_injection_candidate_activity`) from `dynamic_validation.py` and their worker/server registrations; keep any shared helpers still used elsewhere. (Whole `dynamic_validation.py` + orphaned `idor_validation.py` deleted — both were an orphaned pair; surviving HTTP machinery is `dynamic_http.py`.)

## 3. Remove orphaned UI / API / persistence surface

- [x] 3.1 Delete `src/quarry_tui/screens/attack_surface.py`, `src/quarry_tui/widgets/route_table.py`, and their nav wiring in `tui/app.py`. (Dashboard now opens findings directly; `test_route_table.py` deleted.)
- [x] 3.2 Remove the `GET /scans/{id}/attack_surface` route and any client method that calls it. (Route, `QuarryClient.get_attack_surface`, and `replay_scan` attack-surface load removed.)
- [x] 3.3 Remove the `attack_surface_items` table definition and its repository accessors; decide table-drop handling per design D4. (Record class + save/load accessors + repo.py persist ops removed; D4 = drop table, no migration.)
- [x] 3.4 Remove the attack-surface block from the report template and delete its golden coverage of that block. (Template section + `attack_surface` plumbing removed across `reporting.py`/`RenderReportInput`; also removed now-orphaned `AttackSurfaceItem` schema, `ATTACK_SURFACE` ArtifactKind, and the seven orphaned static input types.)

## 4. Rename misleading coverage fields (TDD)

- [x] 4.1 Update `CoverageLedger` / `CoverageGap` field names to agentic-unit names in `schemas.py`; update `coverage.py`, `reporting.py`, and every reader. (`attack_surface_items_total/scanned` → `agent_tasks_total/scanned`; `CoverageGap.attack_surface_item_id` → `scope_unit_id`. Finding/DynamicEvidenceLink `attack_surface_item_id` left as-is — out of scope.)
- [x] 4.2 Update golden report fixtures and coverage tests to the renamed labels.

## 5. Encode the invariant + gate

- [x] 5.1 Add a `RunScanWorkflow` test asserting every candidate finding traces to a hunt agent task (no static producer can re-enter as a source). (`tests/integration/test_agentic_candidate_sourcing.py`.)
- [x] 5.2 Run the full suite (`task test`) and `task lint`; both must pass on a net-smaller codebase. (1537 passed; ruff + pyright + ruff-format + prompt-lint all clean; net −2843 lines, 18 files deleted.)
