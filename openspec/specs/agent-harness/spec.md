# agent-harness Specification

## Purpose

Every agentic stage (recon, hunt, validate, gapfill, prove, trace, dynamic-validate,
live-recon, exploit) runs on one shared multi-turn engine, `run_agent_loop`, rather than
bespoke per-stage loops. Centralizing the loop is what makes caps, guards, scrubbing, and
stop reasons uniform and auditable. The loop runs only inside activities, never in
workflow code.

## Requirements

### Requirement: Single agent loop for all stages

All agentic stages SHALL execute through `run_agent_loop`. The loop SHALL run inside
activities only, never in Temporal workflow code.

#### Scenario: Loop runs in an activity

- **WHEN** an agentic stage needs to reason and call tools
- **THEN** it invokes `run_agent_loop` from within an activity, not from workflow code

### Requirement: Bounded by explicit stop reasons

The loop SHALL terminate with exactly one stop reason from the closed set:
`final_answer`, `max_iterations`, `budget_exceeded`, `guard_triggered`,
`reasoning_rejected`, `schema_rejected`, or `tool_call_cap`. Iteration count, per-role
tool-call cap, and cost budget SHALL each bound the loop.

#### Scenario: Iteration cap halts the loop

- **WHEN** the loop reaches `max_iterations` without a final answer
- **THEN** it returns with `stop_reason="max_iterations"`

#### Scenario: Budget exhaustion halts the loop

- **WHEN** cumulative cost reaches the role's budget during the loop
- **THEN** it returns with `stop_reason="budget_exceeded"`

#### Scenario: Tool-call cap halts the loop

- **WHEN** issued tool calls reach the per-role `tool_call_cap`
- **THEN** it returns with `stop_reason="tool_call_cap"`

### Requirement: Malformed output is repaired, not crashed

When model output fails schema parsing the loop SHALL re-prompt for repair up to a bounded
number of retries that do NOT consume the iteration budget, and SHALL stop with
`schema_rejected` on exhaustion. A non-parse provider failure (timeout, error) SHALL burn
an iteration with corrective feedback rather than crashing the activity. This repair path exists
because open models served via OpenAI-compatible endpoints (e.g. Qwen, DeepSeek, Kimi via Chutes)
routinely emit prose-wrapped or truncated JSON.

#### Scenario: Prose-wrapped JSON is repaired

- **WHEN** a model returns malformed or prose-wrapped JSON
- **THEN** the loop re-prompts for a schema-valid response without advancing the iteration
  counter

#### Scenario: Repair exhaustion stops cleanly

- **WHEN** repair retries are exhausted
- **THEN** the loop returns `stop_reason="schema_rejected"` rather than raising

### Requirement: Tool results are scrubbed and wrapped

Tool results returned into the loop SHALL be passed through the redaction chokepoint and
wrapped as untrusted target content before re-entering a model turn.

#### Scenario: Tool output is untrusted content

- **WHEN** a tool returns output that re-enters the model
- **THEN** it is scrubbed and wrapped as target content, never as instruction
