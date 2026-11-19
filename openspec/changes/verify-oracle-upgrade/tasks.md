# Tasks: verify-oracle-upgrade

## 1. Add timing and differential evidence fields to schemas

- [ ] Add `injected_delay_ms: int | None = None` to `HttpRequestSpec` in
  `src/quarry/schemas.py:1403-1425` — declared by the proposing agent alongside
  the delay payload; absent → differential path (R1 S4), the timing path never guesses.
- [ ] Add `injected_values: tuple[str, ...] | None = None` to `HttpRequestSpec` —
  declared by the proposing agent alongside the payload (the exact substrings injected
  into the request); this is the SOURCE of `LiveProbeEvidence.injected_values`.
- [ ] Add `indicator: str | None = None` to `HttpRequestSpec` for
  hunter-supplied success markers.
- [ ] Add `elapsed_ms: int | None = None` to `LiveProbeEvidence` in
  `src/quarry_activities/verdict_evaluators.py:98-111` for timing-probe latencies.
- [ ] Add `injected_values: tuple[str, ...] | None = field(default=None)` to
  `LiveProbeEvidence` — set at workflow dispatch from `HttpRequestSpec.injected_values`
  (mirrors `body_text`/`status_code`); never derived by diffing or regex-guessing at dispatch.
- [ ] Add `indicator: str | None = None` to `LiveProbeEvidence` — transported from
  `HttpRequestSpec` at dispatch time.
- [ ] Add `timing_profile: bool = False` to `EvaluatorSpec` (verdict_evaluators.py)
  — explicit flag for timing-oracle classes; replaces `min_probes ≥ 5` heuristic.
- [ ] Verify backward compatibility: all existing evaluator tests green with
  new fields at their defaults.
- [ ] GUARD: `uv run pytest tests/unit/test_verdict_evaluators.py -v` — all 16
  existing evaluator tests green with no modifications needed.

## 2. Implement payload-echo normalization helper

- [ ] Add `_normalize_body(body: str, injected_values: tuple[str, ...]) -> str` pure
  function in `src/quarry_activities/verdict_evaluators.py` that replaces every
  occurrence of each injected value with `§INJECTED§` placeholder.
- [ ] The injected-values list SHALL be received from `LiveProbeEvidence.injected_values`
  (set at workflow dispatch from `HttpRequestSpec.injected_values`, declared by the
  proposing agent alongside the payload).
- [ ] Unit test: body `a=1' OR '1'='1` with injected `("1' OR '1'='1",)` normalizes to
  `a=§INJECTED§`.
- [ ] Unit test: body with two distinct injected values `x=foo&y=bar` with injected
  `("foo", "bar")` normalizes to `x=§INJECTED§&y=§INJECTED§`.
- [ ] GUARD: `uv run pytest tests/unit/test_verdict_evaluators.py -k test_normalize_body -v`
  — 3+ tests green.

## 3. Implement token-Jaccard similarity helper

- [ ] Add `_token_jaccard(a: str, b: str) -> float` pure function in
  `src/quarry_activities/verdict_evaluators.py` that splits both bodies on whitespace,
  builds token sets, and returns |intersection| / |union|.
- [ ] Both-empty bodies SHALL return 1.0 (two empty sets are identical). Body
  resolution happens in the evaluator: any unresolvable (None) body SHALL return
  inconclusive BEFORE normalization/Jaccard, never an error (verdict_evaluators.py
  :266-267 sql / :305-306 ssrf) — `_token_jaccard` itself receives only resolved `str`.
- [ ] Unit test: identical bodies → 1.0; both-empty → 1.0; one empty + one non-empty
  → 0.0; disjoint bodies → 0.0; one overlapping token → low fraction.
- [ ] GUARD: `uv run pytest tests/unit/test_verdict_evaluators.py -k test_token_jaccard -v`
  — 5+ tests green.

## 4. Implement indicator-based verdict helper

- [ ] Add `_indicator_verdict(attack_body: str | None, baseline_body: str | None,
  indicator: str) -> str | None` pure function in
  `src/quarry_activities/verdict_evaluators.py`:
  `indicator` in attack body only → `LIVE_CORROBORATED`;
  absent from both → `LIVE_NOT_CORROBORATED`;
  present in both → `None` (fall through to generic heuristics).
- [ ] Indicator matching SHALL check raw (pre-normalization) bodies.
- [ ] Unit test: present-in-attack-only → corroborated; absent-in-both →
  not-corroborated; present-in-both → None; indicator is `None` → returns None
  immediately (no-op).
- [ ] GUARD: `uv run pytest tests/unit/test_verdict_evaluators.py -k test_indicator_verdict -v`
  — 4+ tests green.

## 5. Extend sql_injection_evaluator with composition dispatch

- [ ] Refactor `sql_injection_evaluator` to dispatch internally:
  (a) when `injected_delay_ms` is present on the primary probe evidence → route to
  internal timing statistical path (task 6); (b) when absent → route to differential
  hardening path: extract `injected_values` from evidence, run payload-echo
  normalization on both bodies, check `indicator` on raw bodies first (delegate to
  `_indicator_verdict`), compute token-Jaccard similarity — ≥0.95 + matching status →
  not-corroborated, ≥0.95 + differing status → inconclusive (per R5), below 0.95 →
  fall through to exact-body-comparison.
- [ ] Preserve the base early returns BEFORE the hardening steps (indicator →
  normalization → Jaccard → exact comparison): no-additional → inconclusive;
  non-2xx primary → inconclusive; any unresolvable (None) body → inconclusive
  (verdict_evaluators.py:264-265 / :266-267 sql, :303-304 / :305-306 ssrf) —
  never an error, and None bodies never reach normalization or Jaccard.
- [ ] Apply identical differential hardening to `ssrf_evaluator`.
- [ ] The `default_evaluator` SHALL remain untouched.
- [ ] GUARD: `uv run pytest tests/unit/test_verdict_evaluators.py -v` —
  existing SQLi/SSRF evaluator tests green; new tests for echo-normalization,
  Jaccard-equivalence, indicator-override, and high-similarity-mismatched-status paths.
- [ ] GUARD: `uv run pytest tests/unit/test_per_class_verdict_evaluators.py -v` —
  existing per-class evaluator behavior tests green.

## 6. Implement internal timing statistical path

- [ ] Add `VerdictReceipt` frozen dataclass in `src/quarry_activities/verdict_evaluators.py`
  with fields: N, M, baseline_median, attack_median, mad, robust_sigma,
  classical_sigma, threshold, induced_delay_ms, majority_count, majority_required,
  ladder_scale_factor (None until ladder runs), reason.
- [ ] Add `_timing_evaluate(ev: LiveProbeEvidence, injected_delay_ms: int) ->
  tuple[Verdict, VerdictReceipt]` internal function in
  `src/quarry_activities/verdict_evaluators.py`, called from `sql_injection_evaluator`
  when `injected_delay_ms` is present.
- [ ] N=5 baseline latencies from `ev.additional[0:N]` and M−1=2 attack latencies
  from `ev.additional[N:]` (primary probe = `ev` itself is the first attack probe;
  See M4 evidence shape: primary=first attack, additional=N baseline then M−1 attack).
- [ ] Compute: median baseline and median attack via `statistics.median`; induced delay
  = median_attack − median_baseline; MAD from baseline median; robust sigma = MAD ×
  1.4826; classical sigma = `statistics.stdev`; noise floor σ = max(classical, robust)
  (conservative: an outlier can only make proving HARDER).
- [ ] Threshold = max(3 × σ, 0.6 × injected_delay_ms). Majority: count how many attack
  samples are at or above baseline_median + injected_delay_ms/2 (inclusive, timing.go:136
  `d >= cut`); require ≥ ⌈M/2⌉ (ceil, so M=3 needs 2).
- [ ] Verdict per source's switch (timing.go:136-158): (i) induced ≥ threshold AND
  majority ≥ ⌈M/2⌉ → statistical pass (return "pass" marker for ladder; inclusive,
  timing.go:143 `induced >= strong`); (ii) induced < 3σ → not-corroborated;
  (iii) otherwise → inconclusive.
- [ ] Return a `(verdict, VerdictReceipt)` tuple carrying every field defined above.
- [ ] Unit test: clear injection delay → statistical pass; negligible delay →
  not-corroborated; mixed bag → inconclusive; zero baseline variance →
  threshold = 0.6 × injected_delay (MAD=0, so noise floor = max(0, 0.6×delay) =
  0.6×delay — still rational).
- [ ] GUARD: `uv run pytest tests/unit/test_verdict_evaluators.py -k test_timing_path -v`
  — 6+ tests green.

## 7. Implement delay-ladder confirmation

- [ ] The workflow dispatches a ladder batch of M=3 attack probes at 2× injected_delay_ms
  when `_timing_evaluate` returns a statistical pass marker. The ladder probes SHALL
  re-invoke `_timing_evaluate` against the INITIAL baseline (no fresh baseline).
- [ ] Ladder batch evidence: primary = first ladder attack probe, additional =
  initial baseline probes (N entries, no fresh baseline) then remaining M−1 ladder
  attack probes.
- [ ] Ladder induced = median(ladder-attack) − initial-baseline-median.
  Scale = ladder_induced / first_induced.
- [ ] Corroborated: scale ∈ [1.4, 2.6] AND ladder_induced ≥ first_induced +
  0.6 × injected_delay_ms. Inconclusive when either conjunct fails (ambiguous,
  not proof — timing.go:174-179).
- [ ] When ladder clears: return `LIVE_CORROBORATED` with `ladder_scale_factor` in receipt.
  When ladder fails: return `LIVE_INCONCLUSIVE` with reason `"ladder_failed_to_scale"`.
- [ ] Unit test: scale 2.0× → corroborated; 1.1× → inconclusive; scale 1.5× but
  fails additive floor at low induced → inconclusive.
- [ ] GUARD: `uv run pytest tests/unit/test_verdict_evaluators.py -k test_timing_ladder -v`
  — 4+ tests green.

## 8. Extend workflow timing-probe dispatch

- [ ] In `src/quarry_workflows/run_scan.py`, extend the dynamic-validation probe loop
  to detect timing-oracle evaluators via `EvaluatorSpec.timing_profile` flag
  (NOT `min_probes ≥ 5` heuristic).
- [ ] For timing classes: dispatch N=5 baseline probes (clean parameter — no injected
  delay payload), then dispatch M=3 attack probes (with the injected delay payload),
  collecting `HttpResponseCapture` objects with their `elapsed_ms` values.
- [ ] Assemble timing evidence: primary = first attack probe (`LiveProbeEvidence` with
  `elapsed_ms`, `indicator`, and `injected_values` set from `HttpRequestSpec` — the
  last from `HttpRequestSpec.injected_values`, declared by the proposing agent),
  additional = N baseline probes (each with `elapsed_ms=None` propagates) then
  M−1 remaining attack probes.
- [ ] Ladder re-probe: when `_timing_evaluate` returns a statistical pass marker,
  dispatch M=3 attack probes at 2× injected_delay_ms. The ladder evidence assembles
  as: primary = first ladder attack, additional = initial baseline probes (N) then
  M−1 ladder attack probes (no fresh baseline).
- [ ] Every timing probe SHALL pass through `_dispatch_dynamic_probe` (the single
  egress funnel with `allowed_hosts` + scope-exclusion enforcement).
- [ ] GUARD: `uv run pytest tests/integration/test_dynamic_validate_stage.py
  tests/integration/test_dynamic_validate_stage_gate.py
  tests/golden/test_sqli_differential_probe.py -v` — existing dynamic-validation
  integration tests green; new timing-specific integration tests green.

## 9. Budget accounting for timing probes

- [ ] Add loop-local `timing_probes_remaining: int` counter in the dynamic-validation
  stage, initialized from a configurable limit (default 20).
- [ ] Each timing HTTP request (baseline, attack, or ladder) SHALL decrement
  `timing_probes_remaining` before dispatch.
- [ ] Ladder re-probe only dispatches when `timing_probes_remaining` ≥ M (3).
- [ ] When the initial statistical pass clears but `timing_probes_remaining` < M,
  record `LIVE_INCONCLUSIVE` with reason `"budget_exhausted"` — corroborated
  requires the ladder, never a partial statistical verdict.
- [ ] When counter exhausted mid-batch, return `LIVE_INCONCLUSIVE` with reason
  `"budget_exhausted"` — never a partial statistical verdict.
- [ ] Timing probes SHALL be non-retryable (single attempt per request).
- [ ] GUARD: `uv run pytest tests/unit/test_workflow_differential_dispatch.py -k test_timing_budget -v`
  — 3+ tests green (budget exhausted mid-batch, budget sufficient, ladder skipped on
  budget exhaustion; the budget gate is workflow-side state, so its contracts follow
  this file's established source-assertion + pure-helper pattern for run_scan gates).

## 10. Register evaluator with timing-profile flag

- [ ] In `register_builtin_evaluators` (verdict_evaluators.py:325), ensure
  `sql_injection_evaluator` is registered for `VulnerabilityClass.SQL_INJECTION`
  with `min_probes=2` AND `timing_profile=True` (the evaluator handles BOTH
  differential pairs and timing batches internally via composition dispatch).
- [ ] The evaluator is NOT replaced — it stays `sql_injection_evaluator` and gains
  the internal timing path. The `timing_profile` flag tells the workflow to dispatch
  N+M timing probes when a probe carries `injected_delay_ms`.
- [ ] GUARD: `uv run python -c "
  from quarry_activities.verdict_evaluators import resolve_evaluator_spec;
  from quarry.schemas import VulnerabilityClass;
  spec = resolve_evaluator_spec(VulnerabilityClass.SQL_INJECTION);
  assert spec.timing_profile is True;
  assert spec.min_probes == 2
  "` exits 0.

## 11. Wire timing receipt onto finding.dynamic_validated event

- [ ] Add `evaluate_live_verdict_with_receipt(cls, ev) -> tuple[Verdict,
  VerdictReceipt | None]` in `src/quarry_activities/verdict_evaluators.py`,
  mirroring `evaluate_live_verdict_with_source` (:193-207): returns the verdict
  and, when the timing path ran, the `VerdictReceipt` (defined in task 6); `None`
  otherwise. Evaluators remain pure `LiveProbeEvidence -> Verdict` callables with
  no event access.
- [ ] The workflow SHALL call `evaluate_live_verdict_with_receipt` and serialize a
  non-None receipt into the `finding.dynamic_validated` event payload as a
  `timing_receipt` dict (serialized from `VerdictReceipt`) alongside the existing
  `verdict_source` and `probe_count` fields.
- [ ] Unit test: `evaluate_live_verdict_with_receipt(SQL_INJECTION, timing_evidence)`
  returns a `VerdictReceipt` with all enumerated fields and `ladder_scale_factor`
  ≈ 2.0; non-timing evidence returns `(verdict, None)`.
- [ ] GUARD: `uv run pytest tests/unit/test_verdict_evaluators.py -k test_timing_receipt -v`
  — 2+ tests green.

## 12. Attribution and third-party notices

- [ ] Add a `Pentest-Swarm AI (AGPL-3.0)` entry to `THIRD_PARTY_NOTICES.md` naming
  the oracle mechanism source files (`internal/swarm/verify/oracle/timing.go:106-182`,
  `internal/swarm/verify/oracle/differential.go:98-196`) and stating that Quarry
  re-derives the statistical and set-operation mechanisms in Python with no code
  import.
- [ ] Add attribution comment in `verdict_evaluators.py` above the timing and
  differential hardening sections: `# Oracle mechanisms derived from Pentest-Swarm AI
  (AGPL-3.0, swarm/verify/oracle/{timing,differential}.go) — re-derived as pure
  statistics; see THIRD_PARTY_NOTICES.md.`
- [ ] GUARD: `grep -q "Pentest-Swarm AI" THIRD_PARTY_NOTICES.md && echo OK` exits 0.

## 13. Validate, commit, and push

- [ ] `npx openspec validate verify-oracle-upgrade --strict` exits 0.
- [ ] Verify no name collision: `grep -r "verify-oracle" openspec/specs/
  openspec/changes/archive/ 2>/dev/null` returns zero hits (change id is unique).
- [ ] `git add openspec/changes/verify-oracle-upgrade/ THIRD_PARTY_NOTICES.md &&
  git commit -m "spec: revise verify-oracle-upgrade — close r2 B5/S1-S7/n1-n2"`.
- [ ] Push branch `spec/verify-oracle-upgrade` to origin (try `gh auth setup-git &&
  git push -u origin spec/verify-oracle-upgrade`; park locally on credential failure).
- [ ] Report commit SHA in run metadata.