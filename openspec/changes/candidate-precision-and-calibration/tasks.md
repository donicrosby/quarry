## 1. Schema foundation (finding model)

- [x] 1.1 Write failing tests for an ordered sink-first evidence path on the finding schema (sink at index 0, repo-relative `path:line`, order preserved through persist/re-read) and verify they fail (Red)
- [x] 1.2 Add the ordered evidence-path field to `src/quarry/schemas.py`, keeping `source_refs` for back-compat, and verify 1.1 passes (Green)
- [x] 1.3 Write failing tests for calibrated-severity fields (raw severity retained, calibrated severity/priority, firing-rule ids) and verify they fail
- [x] 1.4 Add the calibrated-severity fields to the finding schema and verify 1.3 passes
- [x] 1.5 Write failing tests for fail-safe verdict defaults (deployment intent defaults to production unless all signals false; missing-file/out-of-range re-verification defaults to retain) and verify they fail
- [x] 1.6 Add verdict-default semantics/types to the schema and verify 1.5 passes, then `ruff format` before staging

## 2. Knowledge Base recon activity

- [x] 2.1 Write failing tests that a KB artifact set (entities, vuln-class notes, dependency graph, root index) is produced before hunt and persisted to the artifact store; empty dependency graph is present-not-missing when no imports parse
- [x] 2.2 Add the KB recon prompt template under `prompts/` (read/find/grep only; agent returns structured output, harness writes files) with the Mantis (Apache-2.0, via Shannon) attribution header, and verify render tests
- [x] 2.3 Implement the KB recon activity (structured output → artifacts), register it in server + worker + tests per the sandboxed-runner rules, and verify 2.1 passes
- [x] 2.4 Write and pass a test that a KB assertion lacking a cited source location is corrected/omitted rather than asserted (grounding spot-check)

## 3. KB consumption by reference (context injector)

- [x] 3.1 Write failing tests that hunt/gapfill/validate invoked with KB references receive the referenced record content as context
- [x] 3.2 Extend the context injector to resolve KB references into rendered prompts, with inline-context fallback when references are absent, and verify 3.1 passes

## 4. Calibration stage

- [x] 4.1 Write failing tests for the calibrate stage: runs only on validated candidates, emits calibrated severity/priority + firing-rule ids, retains raw severity
- [x] 4.2 Add the calibration rule-catalogue prompt under `prompts/calibrate/` with Mantis/Shannon attribution header, and verify render tests
- [x] 4.3 Implement code-side hard caps that must not depend on model compliance (e.g. not-reproduced ⇒ never CRITICAL; self-contained blast radius ⇒ cap MEDIUM) with unit tests
- [x] 4.4 Implement the calibrate activity, register in server + worker + tests, wire it after validation in `run_scan.py`, and verify 4.1 passes
- [x] 4.5 Add a test that a rejected candidate is not calibrated and not reported

## 5. Adversarial-validation checklist verdict

- [ ] 5.1 Write failing tests for the checklist verdict: default-false-positive stance, one outcome per constraint, source-coherence rejects nonexistent cited locations, trust-boundary rejects unreached sinks
- [ ] 5.2 Expand `prompts/validate/refute` into the negative-constraint checklist (default-FP, ignore finder reasoning, itemized constraints) with attribution header; keep neutral-claim-only input; verify render tests
- [ ] 5.3 Implement boundary enforcement of checklist invariants (a FAIL requires a rejecting verdict; non-rejecting verdicts carry no FAIL) that refuses invalid verdicts with an actionable error, and verify 5.1 passes
- [ ] 5.4 Add a feature flag so the validator falls back to the current binary refuter when the checklist is disabled, with a test covering both paths

## 6. Coverage guarantee + exploratory injection

- [ ] 6.1 Write failing tests that the coverage ledger marks every production file covered / intentionally-excluded / gap, and surfaces an unassigned production file as a gap
- [ ] 6.2 Implement ledger-side production-file accounting (deterministic gap computation, boundary-based exclusion recording) and verify 6.1 passes
- [ ] 6.3 Write failing tests that the gapfill planner injects a bounded configurable fraction of unconstrained exploratory investigations (no threat-model context)
- [ ] 6.4 Add the exploratory-investigation planner behavior + single config knob (default in the 25–50% band) to hunt/gapfill prompts and config, and verify 6.3 passes
- [ ] 6.5 Add a hunt-stage test that an unconstrained exploratory task treats a low-risk area's inputs as untrusted (ignores safety assumptions)

## 7. Dedup cutover and integration

- [ ] 7.1 Switch finding-fingerprinting/dedup to key on the sink locator + title, with tests over the sink-first path
- [ ] 7.2 Retire reliance on unordered `source_refs` once the ordered path is populated end to end, verifying no stage still reads it
- [ ] 7.3 Update `THIRD_PARTY_NOTICES` and the `openspec/config.yaml` attribution list to name Mantis (Apache-2.0) via Shannon, and verify the governance/attribution test passes
- [ ] 7.4 Run the full test suite and a benchmark scan; verify calibrated severities, checklist verdicts, KB artifacts, and coverage accounting appear end to end and no regression against the current benchmark
