# Tasks: finding-contract

## 1. Schema: `SeverityRationale` model + fields

- [ ] 1.1 Write failing tests for `SeverityRationale` model: valid construction, missing `impact` raises `ValidationError`, evidence pointers are valid indices, `legacy` flag default `false`, `model_omitted` flag default `false`; verify fail (Red)
- [ ] 1.2 Implement `SeverityRationale` in `src/quarry/schemas.py` (three required text slots, optional `evidence_refs` list, `legacy` bool, `model_omitted` bool); verify 1.1 passes (Green)
- [ ] 1.3 Write failing tests for `CandidateFinding.severity_rationale` as required field: explicit `severity_rationale=null` raises `ValidationError`, serialization round-trips it, JSON deserialization of a pre-contract payload (no `severity_rationale` key) defaults to legacy rationale; verify fail
- [ ] 1.4 Add `severity_rationale: SeverityRationale` field on `CandidateFinding` with a `@model_validator(mode="before")` backfill that sets a legacy-flagged default when the key is absent from raw input; verify 1.3 passes
- [ ] 1.5 Write failing tests for `FinalFinding.severity_rationale`: field is present and non-optional, serialization round-trips, legacy backfill works; verify fail
- [ ] 1.6 Add `severity_rationale` field on `FinalFinding` with same legacy backfill pattern; verify 1.5 passes

## 2. Hunt parser: extract rationale from model output

- [ ] 2.1 Write failing tests for `_parse_finding` with model output that includes `severity_rationale` sub-object (`impact`/`exploitability`/`reachability`): parser extracts and populates the field with `model_omitted=false`; verify fail
- [ ] 2.2 Extend `_parse_finding` in `src/quarry_activities/hunt.py` to read `raw.get("severity_rationale", {})` and construct a `SeverityRationale`; verify 2.1 passes
- [ ] 2.3 Write failing tests for `_parse_finding` with model output that omits `severity_rationale`: parser still produces a valid `CandidateFinding` with `model_omitted=true` and each slot set to the disclosure text; verify fail
- [ ] 2.4 Implement the `model_omitted` fallback path in `_parse_finding`; verify 2.3 passes

## 3. Promotion: carry rationale to `FinalFinding`

- [ ] 3.1 Write failing tests for `promote_to_final_finding_metadata` (or the workflow-level promotion logic) asserting that `severity_rationale` is copied from `CandidateFinding` to `FinalFinding` verbatim; verify fail
- [ ] 3.2 Implement rationale propagation in the promotion path (workflow-level `build_final_finding` or equivalent — grep for `FinalFinding(` construction sites); verify 3.1 passes

## 4. Report: render structured severity sections

- [ ] 4.1 Write failing tests for `_render_markdown_report_impl` with a `FinalFinding` carrying a populated `severity_rationale`: output includes "Impact", "Exploitability", and "Reachability" subsections; verify fail
- [ ] 4.2 Update the report template in `src/quarry_activities/reporting.py` (`REPORT_TEMPLATE`) to render rationale sections for each final finding, with evidence pointers as links; verify 4.1 passes
- [ ] 4.3 Write failing tests for report rendering with a `legacy` finding and a `model_omitted` finding: each renders the appropriate disclosure text rather than fabricating plausible rationale; verify fail
- [ ] 4.4 Implement the disclosure-rendering branches in the template; verify 4.3 passes

## 5. `ValidatorClaim` boundary: exclude rationale

- [ ] 5.1 Write failing tests asserting that `ValidatorClaim` constructed from a `CandidateFinding` does NOT include `severity_rationale` (ADR-021: the validator must not see the hunter's severity justification); verify fail
- [ ] 5.2 Verify that the existing `ValidatorClaim` construction path already excludes it (the field was added after the claim was defined, so it may already be excluded by construction); if it leaks through, add an explicit exclusion; verify 5.1 passes

## 6. Golden fixture + integration

- [ ] 6.1 Update all golden report fixtures (`tests/golden/report_*.md`) to reflect the new severity rationale sections (legacy disclosure for existing fixtures, populated sections for any fixture that exercises the new path)
- [ ] 6.2 Run full unit suite (`uv run pytest tests/unit -q -n 4`) and confirm no regressions
- [ ] 6.3 Run lint + typecheck (`uv run ruff check . && uv run pyright`) clean
- [ ] 6.4 `npx openspec validate finding-contract --strict` clean; tick all boxes in the landing commit

## 7. (Follow-on) Prompt template updates

- [ ] 7.1 Add `severity_rationale` output schema to each hunt class prompt (`prompts/hunt/*.j2`) as an ADDITIONAL task — this is a prompt-registry change, not a schema change, and is tracked separately. The schema + parser work above is complete and independent of prompt updates.

## Execution order

1 → 2 → 3 → 4 → 5 → 6. Task 7 is a follow-on that unblocks only after 1-6 land. 1.1-1.6 are the critical path — everything else depends on the schema being defined.