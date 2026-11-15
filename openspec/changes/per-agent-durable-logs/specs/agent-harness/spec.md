## ADDED Requirements

### Requirement: Per-agent durable execution log

Every invocation of `run_agent_loop` SHALL produce an append-only JSONL log in the
artifact store at `agents/<scan_id>/<role>/<instance_id>.jsonl`. The log SHALL be
written through the same `ArtifactStore` protocol used by other artifact writes. A
missing or unavailable store SHALL cause the loop to skip logging rather than fail.

#### Scenario: Log is written to artifact store

- **WHEN** an activity calls `run_agent_loop` with an `agent_instance_id` and an
  artifact store reference
- **THEN** each tool dispatch, tool result, model call, and the final stop reason
  are appended as JSONL lines to `agents/<scan_id>/<role>/<instance_id>.jsonl`

#### Scenario: Missing store is silently skipped

- **WHEN** an activity calls `run_agent_loop` without an artifact store reference
- **THEN** the loop runs normally and no log file is written

### Requirement: Log entry schema

Each JSONL line SHALL carry at minimum a `timestamp` (ISO 8601 UTC), an `event`
type (`tool_call`, `tool_result`, `model_call`, `stop`), and an `iteration`
counter. A `tool_call` entry SHALL include the tool name and redacted inputs. A
`tool_result` entry SHALL include the scrubbed output text. A `model_call` entry
SHALL include the `ModelInvocation.id` so the log line and the invocation record are
cross-referenced. A `stop` entry SHALL record `stop_reason` and `iterations_used`.

#### Scenario: Tool call is recorded with redacted args

- **WHEN** the loop executes a tool call
- **THEN** a `tool_call` JSONL line is appended with the tool name and inputs passed
  through the same redaction chokepoint used for event payloads

#### Scenario: Tool result is recorded with scrubbed output

- **WHEN** a tool returns output
- **THEN** a `tool_result` JSONL line is appended with the scrubbed output text

#### Scenario: Model call carries invocation cross-reference

- **WHEN** the loop completes a model turn
- **THEN** a `model_call` JSONL line is appended carrying `model_invocation_id`

#### Scenario: Stop reason is always the last line

- **WHEN** the loop terminates for any stop reason
- **THEN** a `stop` JSONL line is appended as the final line, recording
  `stop_reason`, `iterations_used`, and `total_cost`

### Requirement: Deterministic instance ID survives replay

The instance ID SHALL be computed from `scan_id`, `role`, and a task-specific
suffix (the `AgentTask.id` prefix) so replaying the same task with the same inputs
produces the same instance ID and appends to the same log file. Log writes SHALL be
append-only — a replay SHALL NOT truncate or overwrite existing log lines.

#### Scenario: Same task produces same instance ID

- **WHEN** a hunt task with `scan_id="s1"` and `task_id="abc123..."` runs, then is
  replayed with the same `scan_id` and `task_id`
- **THEN** both runs append to `agents/s1/hunt/hunt-abc123.jsonl`

#### Scenario: Replay never truncates

- **WHEN** a replay appends to an existing log file
- **THEN** the file contains all lines from both the original run and the replay,
  with no lines removed or overwritten