## Context

Reference-alignment roadmap, Phase 1. Depends on Phase 0
(`remove-static-scan-path`), which removes the two hand-coded per-class dynamic
validators and frees the validator dispatch point.

The `dynamic_validate` seat is provisioned but empty:
- `panel_config.py`: `"dynamic_validate": RoleConfig(provider=MOCK, model="mock-v1", rpm=30)`
- `http_tool.py`: `roles = ["dynamic_validate", "prove"]`
- `runner.py`: `_DYNAMIC_TOOLS = {"http_request", "run_in_sandbox"}`, `allowed_hosts`
  fail-closed, `block_dynamic`
- `dynamic_validation.py`: `run_agent_loop` calls = **0**

Hunt proves the pattern: `run_agent_loop` + a per-class prompt family
(`prompts/hunt/*.j2`, 18 templates) + tools. This change applies that pattern to the
`dynamic_validate` role with the `http_request` tool.

## Goals / Non-Goals

**Goals:**
- Put a real agent in the `dynamic_validate` seat.
- Generalize live validation from 2 hand-coded classes to all agentic classes via a
  per-class dynamic-validation prompt family.
- Place it as a stage between validate and prove, opt-in and fail-closed.
- Reuse every existing dynamic safety guard and provenance mechanism.

**Non-Goals:**
- No multi-step *exploitation* / request chaining beyond corroborating one hypothesis
  (Phase 2). No browser automation (Phase 2). No model-panel ensemble work (Phase 3).

## Decisions

### D1: Agentic corroboration, not a hand-coded checker

Replace the removed per-class `if/else` validators with `run_agent_loop` driving
`http_request`. Rationale: hand-coded checkers only ever covered 2 of 18 classes and
could not adapt; an agent generalizes and can reason about the live responses. This is
the whole point of the pivot.

### D2: Per-class prompts with a generic fallback

Mirror hunt: `prompts/dynamic_validate/<vuln_class>.j2`, falling back to a generic
`dynamic_validate/dynamic_validate.j2` for classes without a specific template.
Rationale: proven ergonomics; lets high-value classes (IDOR, cmdi, SSRF) get precise
live-probe guidance while every class still gets *some* live validation.

Open question deferred to Phase 2: pentesting live apps is often more about request
*chaining* than class-specific patterns. Phase 1 keeps single-hypothesis
corroboration (one candidate → probe → verdict); Phase 2 revisits whether one strong
generic "probe this hypothesis" prompt beats N class-specific ones once chaining and
session state exist.

### D3: Stage between validate and prove

Live corroboration before prove means prove can prioritize (or skip) based on the live
verdict, saving sandbox cost — matching the week-14.5 intent (`resolve_dynamic`
already exists). Alternative (fold into prove) is rejected here because it loses the
cheap early signal; it is reconsidered in Phase 2 when the live and prove roles may
merge into one exploitation loop.

### D4: Opt-in, fail-closed authorization (ADR-017 unchanged)

`--dynamic-validation` remains the sole authority for live traffic; a target alone
never enables it. Flag-without-target is rejected at launch (existing CLI guard).
Default scans send zero live traffic.

### D5: Reuse provenance + evidence machinery

Loop invocations already carry provenance (shipped `loop-invocation-provenance`); seed
prompts persist under byte-storing retention (shipped `scan-prompt-persistence`). HTTP
evidence uses the existing `DynamicEvidenceLink` / capture schemas. No new provenance
surface.

## Risks / Trade-offs

- **[Live-validation false confidence]** an agent that "confirms" from an ambiguous
  response. → Mitigation: require captured request/response evidence for a
  `corroborated` verdict; `inconclusive` is a first-class outcome, not forced to a
  boolean.
- **[Cost of a per-candidate live loop]** → bounded by scan budget and by running only
  on validate survivors; the stage is opt-in.
- **[Prompt sprawl]** 18 more templates. → Mitigation: ship a strong generic template
  first, add per-class ones only where they measurably help; `prompt-lint` gates them.
- **[Scope/authorization mistakes send real traffic]** → no new egress path; all
  requests go through the existing guarded `http_request` dispatch.

## Migration Plan

- Additive stage, default-off; existing scans are unaffected.
- Rollback: disable the stage / drop the flag wiring; the removed hand-coded
  validators are not restored (Phase 0 owns their removal).

## Open Questions

- One generic dynamic-validation prompt vs. a per-class family at launch? (Lean:
  generic first, then per-class for IDOR/cmdi/SSRF.)
- Does a `not_corroborated` live verdict *downgrade* or *drop* the code finding, or
  just annotate it? Live corroboration failing does not prove the code finding false.
  (Lean: annotate + lower confidence, never silently drop.)
