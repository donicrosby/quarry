# loop-invocation-provenance Specification

## Purpose

Every model-calling activity in Quarry is agentic, so nearly all `ModelInvocation`
records originate inside `run_agent_loop`. The loop previously recorded empty
per-part hashes, which made real scans unverifiable: the ADR-019 provenance
machinery had nothing to check against. This capability carries the hashes the
activity already computed in `build_prompt` into the loop and stamps them on every
turn's invocation, along with the real scan id. It is the prerequisite that makes
stored prompt bytes verifiable.

## Requirements

### Requirement: Loop invocations carry per-part provenance hashes

A `ModelInvocation` minted from within `run_agent_loop` SHALL carry the ADR-019
per-part provenance derived from the activity's rendered prompt: `template_sha256`,
`system_prompt_hash`, `developer_prompt_hash` (when present), `user_prompt_hash`,
`evidence_hashes`, and the template id/version.

These values describe the rendered prompt template that seeded the loop and are
constant for the loop's lifetime; the loop SHALL stamp them on every turn's request
so each turn's invocation is verifiable, even though the conversation history grows.

The activity SHALL supply this provenance to `run_agent_loop` from the
`RenderedPrompt` it already produced via `build_prompt`; the loop SHALL NOT recompute
prompt hashes.

#### Scenario: Loop invocation records the rendered prompt's per-part hashes

- **WHEN** an agentic activity runs `run_agent_loop` with the provenance from its
  `RenderedPrompt`
- **THEN** each resulting `ModelInvocation` has `template_sha256` equal to the
  rendered template's sha256
- **AND** `system_prompt_hash` equals the rendered prompt's `system` part hash
- **AND** `user_prompt_hash` equals the sha256 of the initial user message
- **AND** `evidence_hashes` equals the rendered prompt's evidence hashes

#### Scenario: Provenance is verifiable

- **WHEN** a loop-sourced `ModelInvocation` is checked with `verify_invocation`
  against the rendered prompt's expected system hash and template sha
- **THEN** verification passes (the recorded hashes are non-empty and match)

### Requirement: Loop invocations carry the real scan id

A `ModelInvocation` minted from within `run_agent_loop` SHALL record the real scan
id supplied by the activity, not the `"loop"` placeholder, so per-request identity
(and any storage key derived from it) is correct before persistence.

#### Scenario: Request carries the real scan id

- **WHEN** `run_agent_loop` is called with a concrete `scan_id`
- **THEN** each turn's `ModelRequest` and resulting `ModelInvocation` record that
  `scan_id`
- **AND** no invocation records `scan_id == "loop"`

### Requirement: Backward-compatible when provenance is absent

The loop SHALL behave exactly as before when an activity does not supply
rendered-prompt provenance to `run_agent_loop`: invocations carry empty per-part
hashes and no error is raised. Supplying provenance is additive.

#### Scenario: No provenance supplied

- **WHEN** `run_agent_loop` is called without prompt provenance (e.g. an existing
  test)
- **THEN** the loop runs to completion and its invocations carry empty per-part
  hashes, as they did previously
