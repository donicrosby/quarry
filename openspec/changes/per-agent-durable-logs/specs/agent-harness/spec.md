## ADDED Requirements

### Requirement: Per-agent durable execution log

Every invocation of `run_agent_loop` given an artifact store reference SHALL produce
an append-only JSONL log at `agents/<scan_id>/<role>/<instance_id>.jsonl`, written
through the artifact store via a new `append_bytes` store operation (O_APPEND line
writes in `LocalArtifactStore`) under a new `ArtifactKind.AGENT_LOG` member. A
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

Each JSONL line SHALL carry an `instance_id`, an ISO 8601 UTC `timestamp`, an
`event` type (`tool_call`, `tool_result`, `model_call`, `stop`), an `iteration`
counter, and a `replay` flag (true only on replay lines).
A `tool_call` entry SHALL include the tool name and redacted inputs. A
`tool_result` entry SHALL include the scrubbed output. A `model_call` entry SHALL
include the `ModelInvocation.id` (cross-reference). A `stop` entry SHALL record
`stop_reason`, `iterations_used`, and `total_cost`.

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

The instance ID SHALL be `<role>-<task_id_prefix_8>`: the first 8 chars of the
`AgentTask.id` UUID. `scan_id` scopes the artifact path, so distinct scans never
share a log file. The same task replayed with the same inputs yields the same
instance ID and appends to the same file. Writes SHALL be append-only: a replay
SHALL NOT truncate or overwrite existing lines, and its lines SHALL carry
`replay: true`.

#### Scenario: Same task produces same instance ID

- **WHEN** a hunt task with `scan_id="s1"` and `task_id="abc12345-..."` runs, then
  is replayed with the same `scan_id` and `task_id`
- **THEN** both runs append to `agents/s1/hunt/hunt-abc12345.jsonl`

#### Scenario: Replay never truncates

- **WHEN** a replay appends to an existing log file
- **THEN** the file contains all lines from both the original run and the replay,
  with no lines removed or overwritten