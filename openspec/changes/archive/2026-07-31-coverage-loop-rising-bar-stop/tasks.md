## 1. Yield-bar helper and stop criterion (TDD: red → green)

- [x] 1.1 Write `tests/unit/test_coverage_loop_yield_bar.py` for a new pure `yield_bar(cumulative, f)` helper: `yield_bar(0, 0.15) == 1` and `yield_bar(3, 0.15) == 1` (floor), `yield_bar(10, 0.15) == 2`, `yield_bar(14, 0.15) == 3`, and `yield_bar(c, 0) == 0` for any `c` (disabled).
- [x] 1.2 Extend `tests/unit/` coverage of `should_continue` for the new signature: below-bar yield returns `False` (finding_plateau); at/above-bar returns `True`; `over_budget` and `new_task_count <= 0` still return `False` and take precedence when they and the yield rule both apply; `coverage_yield_threshold == 0` never triggers the yield branch; round-cap still bounds the loop.
- [x] 1.3 Implement `yield_bar(cumulative: int, f: float) -> int` in `src/quarry_workflows/coverage_loop.py` as `0 if f <= 0 else max(1, ceil(f * cumulative))`, kept pure (no I/O, no nondeterminism).
- [x] 1.4 Extend `should_continue(...)` to accept `new_finding_count`, `cumulative_findings`, and `coverage_yield_threshold`, adding the finding-plateau branch *after* the existing `over_budget` and `new_task_count <= 0` checks so precedence is preserved.
- [x] 1.5 Run the tests from 1.1–1.2 to green; run `task lint` / `ruff format`.

## 2. Configuration knob

- [x] 2.1 Write a test that `ScanDefaultsConfig` exposes `coverage_yield_threshold` with default `0.15` and that it round-trips through `quarry.toml` panel/scan-defaults loading.
- [x] 2.2 Add `coverage_yield_threshold: float = 0.15` to `ScanDefaultsConfig` in `src/quarry/panel_config.py`, mirroring how `max_coverage_rounds` is defined and validated (reject negatives).
- [x] 2.3 Thread `coverage_yield_threshold` onto `RunScanWorkflowInput` beside `max_coverage_rounds` (`src/quarry_workflows/run_scan.py`), sourced from scan defaults.
- [x] 2.4 Run tests from 2.1 to green.

## 3. Wire finding-yield into the loop

- [x] 3.1 Write an integration test (`tests/integration/`) driving the loop so that: a round adding new distinct findings at/above the bar continues; a subsequent round whose deduped delta falls below the rising bar stops with `finding_plateau`; and with `coverage_yield_threshold = 0` the same sequence runs to the round cap / task-convergence as today (backward compat).
- [x] 3.2 In `RunScanWorkflow._run`, capture the deduplicated `len(candidate_findings)` before and after each round's dedup, compute the round's new-distinct delta and the pre-round cumulative, and pass them plus `coverage_yield_threshold` into `should_continue`.
- [x] 3.3 Add an assertion/guard (and test) that dedup runs before the stop evaluation each round, so the yield count reflects post-dedup clustering.
- [x] 3.4 Run tests from 3.1 to green.

## 4. Observability: finding_plateau stop reason

- [x] 4.1 Write a test that when the loop stops on the yield bar, the `round.completed` workflow event payload carries a `finding_plateau` stop reason distinct from convergence / round-cap / budget.
- [x] 4.2 Emit the stop reason on the `round.completed` event in `run_scan.py`; derive it from which `should_continue` branch fired (return the reason, or recompute it at the break site).
- [x] 4.3 Write a golden/report test that the rendered report states an early stop due to a finding plateau, distinct from reaching the round cap; update the report renderer (`src/quarry_activities/reporting.py`) accordingly.
- [x] 4.4 Run tests from 4.1 and 4.3 to green.

## 5. Documentation and full-suite gate

- [x] 5.1 Amend `docs/decisions/adr-022-iterative-coverage-loop.md` (in the quarry-plans repo, or the in-repo ADR if mirrored) stop-criteria section to add the rising-bar finding-plateau criterion, the `coverage_yield_threshold` knob, and the disable-with-`0` behavior.
- [x] 5.2 Document the knob and its recall/cost trade-off wherever scan-defaults config is described (e.g. `quarry.toml.example` and any config reference doc).
- [x] 5.3 Resolve the design open question (yield denominator: all distinct findings vs. validated/`needs_proof` only) with the reviewer; if the stricter gate is chosen, thread the filtered count instead of the raw deduped count.
- [x] 5.4 Run the full suite (`task test`) and `task lint`; both must pass.
