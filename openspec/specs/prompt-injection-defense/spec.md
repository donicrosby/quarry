# prompt-injection-defense Specification

## Purpose

Everything the target controls - repository files, tool output, HTTP responses - is
evidence, never instruction. This capability defines the structural defenses that keep
target-controlled content from overriding the system's own rules: a fixed prompt envelope,
untrusted-content wrapping, response size caps, and the rule that scope and focus are
first-party instructions enforced in both prompt and code.

## Requirements

### Requirement: Target content is evidence, never instruction

Target-controlled content SHALL NOT be able to override system or developer instructions,
policies, budgets, safety limits, reporting rules, model routing, integration rules, or
sandbox rules.

#### Scenario: Injected instruction is ignored

- **WHEN** target content contains text instructing the agent to ignore its rules or exfiltrate data
- **THEN** the instruction has no effect on the agent's authorized behavior

### Requirement: Four-part prompt envelope

Prompts SHALL be structured into a system/developer part, a task part, an evidence part,
and an output-schema part, enforced structurally by the prompt envelope rather than by ad
hoc concatenation.

#### Scenario: Evidence occupies its own part

- **WHEN** a prompt is assembled with target-derived evidence
- **THEN** the evidence is placed in the evidence part, not the instruction part

### Requirement: Untrusted content is wrapped

Target-derived content entering a model turn SHALL be wrapped in an untrusted-content
marker (`<target_content>`) so the model can distinguish it from instructions.

#### Scenario: Tool and HTTP output is wrapped

- **WHEN** file content, tool output, or an HTTP response re-enters the model
- **THEN** it is delivered inside the untrusted-content wrapper

### Requirement: Responses are bounded and sanitized

HTTP responses fed to a model SHALL be capped in size (with truncation before the model
turn), sanitized, and have headers kept separate from body.

#### Scenario: Oversized response is truncated

- **WHEN** a target response exceeds the configured size cap
- **THEN** it is truncated before any model turn

### Requirement: Scope and focus are trusted first-party instructions enforced twice

Scope exclusions and focus lists SHALL be delivered as first-party instructions in the
envelope, never inside `<target_content>`, and SHALL also be enforced by a code guard.
Neither the prompt layer nor the code guard SHALL be the sole control.

#### Scenario: Focus is enforced in code even if the prompt is ignored

- **WHEN** a model proposes hunting an out-of-focus class despite the prompt
- **THEN** a code guard still drops the out-of-focus work
