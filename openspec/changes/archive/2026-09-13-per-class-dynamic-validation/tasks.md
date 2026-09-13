## 1. VerdictEvaluator registry

- [x] 1.1 Write failing tests for a `VerdictEvaluator` protocol + registry: register per-class pure functions, look up by `VulnerabilityClass`, fall back to a default status-code evaluator when no class evaluator is registered; verify fail (Red)
- [x] 1.2 Implement `src/quarry_activities/verdict_evaluators.py` (registry + default status evaluator extracted from `live_verdict_from_status`); verify 1.1 passes (Green)
- [x] 1.3 Write failing tests for an SSTI marker evaluator (`{{7*7}}` payload → `49` in body = confirmed) and a SQLi boolean-diff evaluator (true/false probe bodies diverge); verify fail
- [x] 1.4 Implement the ssti + sql_injection evaluators as pure functions over `HttpResponseCapture` pairs; verify 1.3 passes
- [x] 1.5 Wire the registry into the validation path in `run_scan.py`, replacing hardcoded per-class branches; verify existing validation tests still pass (no regression)

## 2. Per-class dynamic_validate prompts

- [x] 2.1 Write failing render tests for each new template (sql_injection, xss, ssti, xxe, file_upload, auth, open_redirect, csrf): template exists, renders with the standard context, includes the class-specific verdict instruction; verify fail (Red)
- [x] 2.2 Author the templates under `prompts/dynamic_validate/`; verify 2.1 passes (Green)
- [x] 2.3 Verify every `VulnerabilityClass` enum member resolves to either a class template or the explicit generic fallback (registry completeness test)

## 3. Missing hunt templates

- [x] 3.1 Write failing render tests for hunt templates xxe, file_upload, csrf; verify fail (Red)
- [x] 3.2 Author the three templates under `prompts/hunt/`; verify 3.1 passes (Green)

## 4. Verify + land

- [x] 4.1 `uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest -x -q` all green
- [x] 4.2 `openspec validate per-class-dynamic-validation --strict`, commit, push, open PR
