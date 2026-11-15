## ADDED Requirements

### Requirement: Agent-controlled environment injection is blocked at the schema layer

The sandbox tool schema SHALL carry no field through which the agent can inject arbitrary
environment variables. The top-level `additionalProperties: false` gate (sandbox_tool.py:82)
and the absence of an `env` / `environment` property SHALL be verified by a conformance test.

#### Scenario: no-env-field-in-tool-schema

- **WHEN** the `run_in_sandbox` tool input schema is inspected
- **THEN** no `env`, `environment`, `env_vars`, or similarly named property exists in `properties`

#### Scenario: unknown-keys-rejected-at-schema-boundary

- **WHEN** a tool call includes an unrecognized top-level key such as `"env": {"PATH": "/evil"}`
- **THEN** the schema validation rejects it before any dispatch occurs

### Requirement: env-profile resolution is fail-safe

The `env_profile` field on `SandboxExecSpec` (schemas.py:1539) SHALL be resolved into
environment variables only through a fixed, enumerated mapping. The resolution SHALL NOT
accept agent-controlled keys or values. Until a resolution implementation ships, any
`env_profile` value other than `"none"` SHALL be rejected at the tool-call boundary.

#### Scenario: repo-readonly-rejected-until-implemented

- **WHEN** the prove agent specifies `env_profile: "repo_readonly"` and no resolution
  implementation is registered
- **THEN** the tool call is refused with a clear error message

#### Scenario: resolution-map-has-no-agent-controlled-values

- **WHEN** an env-profile resolution implementation is registered
- **THEN** every env-var name and value produced originates from a fixed map with no
  string interpolation from agent-supplied fields

### Requirement: Shell environment-setting arguments are rejected

Args passed to sandbox commands SHALL be inspected for shell environment-setting patterns
before execution. Any arg that starts with a `NAME=value` pattern or that is `-e`, `--env`,
`env`, or `printenv` when the command is `sh` or `python3` SHALL be rejected.

#### Scenario: var-equals-value-arg-is-rejected

- **WHEN** the prove agent specifies `args: ["VAR=malicious", "command"]` for command `sh`
- **THEN** the sandbox rejects the arg set before execution

#### Scenario: minus-e-flag-is-rejected

- **WHEN** the prove agent specifies `args: ["-e", "VAR=malicious", "command"]` for command `python3`
- **THEN** the sandbox rejects the arg set before execution

#### Scenario: plain-args-without-env-patterns-are-allowed

- **WHEN** the prove agent specifies `args: ["-c", "echo hello"]` for command `sh`
- **THEN** execution proceeds normally

### Requirement: env command output is restricted

When the `env` command is on the sandbox allowlist (sandbox.py:103), its output SHALL be
post-filtered to redact non-credential environment variables before the capture is stored
as an artifact. Only the exit code SHALL be returned unredacted; env-var names and values
SHALL be replaced with a count line.

#### Scenario: env-output-is-redacted

- **WHEN** the prove agent runs `env` in the sandbox and the process environment contains
  non-credential variables
- **THEN** the stdout artifact contains only a count of variables present, not their names or values

#### Scenario: env-exit-code-is-preserved

- **WHEN** the prove agent runs `env` in the sandbox
- **THEN** the exit code in the SandboxExecCapture is the actual exit code of the env command