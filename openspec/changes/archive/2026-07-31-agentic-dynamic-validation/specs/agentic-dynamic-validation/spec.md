## ADDED Requirements

### Requirement: Agentic corroboration of a candidate against the live target

An agent in the `dynamic_validate` role SHALL corroborate a validated candidate
finding against the authorized live target by driving the `http_request` tool inside
`run_agent_loop`, and SHALL emit a live verdict (corroborated / not-corroborated /
inconclusive) derived from the observed responses.

The agent SHALL be prompted by a per-vulnerability-class dynamic-validation template
(keyed by the candidate's `vuln_class`, mirroring the hunt prompt family), so live
validation is available for every agentic class rather than a hand-coded subset.

#### Scenario: A live-corroborated candidate is marked corroborated

- **WHEN** the dynamic-validation agent sends requests that demonstrate the candidate
  behavior on the live target
- **THEN** the finding records a `corroborated` live verdict
- **AND** the request/response pairs are captured as evidence artifacts linked to the
  finding

#### Scenario: A candidate the live target refutes is not corroborated

- **WHEN** the agent's requests do not reproduce the candidate behavior
- **THEN** the finding records a `not_corroborated` (or `inconclusive`) live verdict
  rather than being dropped or promoted silently

#### Scenario: Per-class prompt selection

- **WHEN** the candidate's `vuln_class` has a dynamic-validation template
- **THEN** that template drives the loop; classes without a specific template fall
  back to a generic dynamic-validation template

### Requirement: Dynamic validation honors all dynamic-tool safety guards

Agentic dynamic validation SHALL send live traffic only through the existing guarded
path: `http_request` is available solely in the `dynamic_validate` (and `prove`)
roles, requests are scope-checked against `allowed_hosts` (fail-closed on an empty
allowlist), scope exclusions are enforced, and credentials are injected only via the
credential cache — never emitted into prompts.

#### Scenario: Out-of-scope host is refused

- **WHEN** the agent proposes an `http_request` to a host not in `allowed_hosts`
- **THEN** the request is refused before any network I/O

#### Scenario: No live traffic without explicit authorization

- **WHEN** dynamic validation runs but live traffic is not authorized (no target /
  flag)
- **THEN** the agent sends no `http_request` and the stage is a no-op (see the
  dynamic-validation-stage capability)

### Requirement: Dynamic-validation invocations are provenance-tracked

Every model invocation made by the dynamic-validation agent SHALL carry loop
provenance (per the shipped loop-invocation-provenance capability), and under a
byte-storing retention mode its seed prompt SHALL be persisted (per
scan-prompt-persistence), so a live verdict is auditable to the exact prompt and model
that produced it.

#### Scenario: Verdict is auditable

- **WHEN** a dynamic-validation verdict is recorded
- **THEN** its `ModelInvocation`(s) carry non-empty per-part provenance hashes and the
  real scan id
