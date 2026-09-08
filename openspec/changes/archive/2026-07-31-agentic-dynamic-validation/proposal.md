## Why

The `dynamic_validate` role is a fully provisioned agent seat with nobody in it. The
role exists (`panel_config.py`), the `http_request` tool is gated to it
(`http_tool.py: roles = ["dynamic_validate", "prove"]`), and the safety layers are
built (`allowed_hosts` fail-closed, `block_dynamic`, credential injection, HTTP
evidence capture) — but `dynamic_validation.py` never calls `run_agent_loop`. Live
validation today is two hand-coded checkers (IDOR, command-injection) that Phase 0
removes. So the agent can *hunt* 18 vulnerability classes in code but can
*dynamically confirm* only 2 — and even those are hardcoded, not agentic.

This is Phase 1 of the reference-alignment roadmap. It puts a real agent in the
`dynamic_validate` seat: an agentic loop that, given a validated code candidate and a
live target, drives `http_request` to corroborate the finding against the running app.
It generalizes live validation from 2 hand-coded classes to all agentic classes, and
it is the foundation the Phase 2 live-exploitation loop builds on.

## What Changes

- Add an **agentic dynamic-validation activity**: `run_agent_loop` in the
  `dynamic_validate` role, driven by per-class dynamic-validation prompt templates
  (mirroring how hunt already keys prompts by vuln class), using the `http_request`
  tool to send scope-checked requests to the authorized target and judging the
  finding from the live responses.
- Add a **dynamic-validation stage** to `RunScanWorkflow`, gated on `--dynamic-validation`
  + a resolved target (ADR-017), placed after agentic validate and before prove so
  live corroboration is available cheaply *before* the expensive prove stage.
- Populate the stage's outcome onto the finding (corroborated / not-corroborated /
  inconclusive) and capture the request/response evidence as artifacts linked to the
  finding, reusing the existing `DynamicEvidenceLink` / HTTP capture schemas.
- Reuse Phase 0's freed dispatch point; no hand-coded per-class validators return.

Non-goals: no live *exploitation* / request chaining beyond single-hypothesis
corroboration (that is Phase 2); no browser automation (Phase 2); no change to the
static path (Phase 0) or the model panel (Phase 3).

## Capabilities

### New Capabilities
- `agentic-dynamic-validation`: an agent in the `dynamic_validate` role corroborates a
  validated candidate against the live target using `http_request`, keyed by
  per-class dynamic-validation prompts, honoring all existing dynamic-tool safety
  guards, and emitting a live verdict plus linked HTTP evidence.
- `dynamic-validation-stage`: a retention/flag-gated pipeline stage that runs agentic
  dynamic validation after validate and before prove, only when live traffic is
  explicitly authorized.

### Modified Capabilities
<!-- No existing openspec/specs/ capability changes its requirements; this builds on
     agentic-candidate-sourcing (Phase 0) and reuses the ADR-017 dynamic tooling. -->

## Impact

- **Code**: new agentic validator in `src/quarry_activities/dynamic_validation.py` (or
  a sibling module) built on `run_agent_loop`; a `dynamic_validate` stage in
  `src/quarry_workflows/run_scan.py`; per-class prompt templates under
  `prompts/dynamic_validate/`.
- **Prompts**: new `prompts/dynamic_validate/*.j2` family, resolved at startup like
  the hunt family; subject to `prompt-lint`.
- **Safety**: reuses `http_request` role gate, `allowed_hosts`, `block_dynamic`,
  scope exclusions, credential injection — no new egress path.
- **Provenance**: dynamic-validation invocations carry loop provenance (per the
  shipped `loop-invocation-provenance`) and, under a byte-storing retention mode, seed
  prompts (per `scan-prompt-persistence`).
- **Depends on**: Phase 0 (`remove-static-scan-path`) for the freed seat and clean
  dispatch point.
