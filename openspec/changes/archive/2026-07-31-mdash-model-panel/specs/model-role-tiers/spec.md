## ADDED Requirements

### Requirement: A role may be served by a tier of models

The model panel SHALL allow a role to be served by a configured tier of models — for
example a SOTA "heavy reasoner," a cheaper distilled "debater" for high-volume passes,
and a second independent SOTA "counterpoint" — where each tier entry carries its own
provider, model, prompt regime, and per-role caps. A role with a single model SHALL
remain valid (the tier degenerates to one entry), preserving current behavior.

#### Scenario: Tiered role dispatches to the right model per function

- **WHEN** a role is configured with reasoner and debater tiers
- **THEN** the heavy-reasoning pass uses the reasoner tier's model and the
  high-volume/refutation pass uses the debater tier's model

#### Scenario: Single-model role still works

- **WHEN** a role is configured with one model (no tiers)
- **THEN** it behaves exactly as today

### Requirement: Per-role model caps are honored

`RoleConfig` (per tier) SHALL support and enforce the per-role caps the reference panel
specifies — at minimum a `tool_call_cap` and optional extended-thinking budget — so a
tier's runtime behavior is bounded by configuration rather than only by global loop
caps.

#### Scenario: tool_call_cap bounds a tier

- **WHEN** a tier declares a `tool_call_cap`
- **THEN** a loop running that tier stops issuing tool calls once the cap is reached
