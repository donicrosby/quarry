## ADDED Requirements

### Requirement: Controlled environment variables with allowlisted names

`SandboxExecSpec` SHALL carry an `env` field restricted to allowlisted variable names
with per-name allowlisted values; non-allowlisted names or values SHALL be rejected at
the schema boundary. Values SHALL be selected from a fixed infrastructure-provided set
per name, never free-form agent strings. The allowlists SHALL include `EDITOR` with
value `/bin/sh` (the vulnerable-cli proof path). The env SHALL be applied to the target
subprocess only; the sandbox runtime SHALL NOT inherit it.

#### Scenario: allowlisted-env-name-is-accepted

- **WHEN** the prove agent specifies `env: {"EDITOR": "/bin/sh"}`
- **THEN** the env var is forwarded to the target subprocess

#### Scenario: non-allowlisted-env-name-is-rejected

- **WHEN** the prove agent specifies `env: {"LD_PRELOAD": "/tmp/evil.so"}`
- **THEN** the tool call is rejected because `LD_PRELOAD` is not on the name allowlist

#### Scenario: non-allowlisted-env-value-is-rejected

- **WHEN** the prove agent specifies `env: {"PATH": "/tmp/attacker"}`
- **THEN** the tool call is rejected because `/tmp/attacker` is not an allowed value for `PATH`

#### Scenario: env-applied-to-subprocess-not-runtime

- **WHEN** env vars are set via the `env` field and the target subprocess executes
- **THEN** the sandbox runtime process does not inherit those variables

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

### Requirement: Arg-level env-setting is defense-in-depth, not the primary defense

Leading args matching a `NAME=VALUE` prefix (the `NAME=VALUE command` and
`env NAME=VALUE command` idioms) SHALL be rejected; non-leading args SHALL NOT be
rejected on this pattern, and `-e`/`--env` SHALL NOT be rejected. This filtering is
defense-in-depth: shell `-c` payloads and inline code can set environment at runtime;
the primary defense is the empty base environment plus credential scrubbing plus
egress gating.

#### Scenario: var-equals-value-arg-is-rejected

- **WHEN** the prove agent specifies an arg starting with `NAME=VALUE` (e.g.
  `args: ["VAR=malicious", "command"]`)
- **THEN** the sandbox rejects the arg set before execution

#### Scenario: shell-c-payload-can-set-env-at-runtime

- **WHEN** the prove agent runs `sh -c "export VAR=malicious; cmd"` or
  `python3 -c "import os; os.environ['VAR']='x'"`
- **THEN** the arg filter does not block it (the `-c` payload is a single arg)
- **THEN** the empty base environment and credential scrubber remain the primary defense

#### Scenario: plain-args-without-env-patterns-are-allowed

- **WHEN** the prove agent specifies `args: ["-c", "echo hello"]` for command `sh`
- **THEN** execution proceeds normally

### Requirement: Environment-dump output is content-keyed redacted

When any allowlisted command produces stdout or stderr matching an env-dump shape, the
sandbox SHALL redact it to a variable-count line on both streams. Detection SHALL be
content-keyed (at least two KEY=VALUE lines, at least half of non-empty lines) and
symmetric across stdout and stderr. The exit code SHALL be preserved. Obfuscated
forms are outside detection scope; credential scrubbing still applies.

#### Scenario: env-command-output-is-redacted

- **WHEN** the prove agent runs `env` in the sandbox
- **THEN** the stdout artifact contains only a count of variables present (e.g.
  `"<N> environment variables present (redacted)"`), not their names or values

#### Scenario: printenv-via-shell-is-redacted

- **WHEN** the prove agent runs `sh -c "printenv"` and stdout matches the env-dump shape
- **THEN** the stdout is content-matched and replaced with the count line

#### Scenario: python-env-dump-is-redacted

- **WHEN** the prove agent runs
  `python3 -c "import os; [print(k + '=' + v) for k, v in os.environ.items()]"`
  and stdout matches the env-dump shape
- **THEN** the stdout is content-matched and replaced with the count line

#### Scenario: stderr-env-dump-is-redacted

- **WHEN** the prove agent runs `sh -c "env 1>&2"` and stderr matches the env-dump shape
- **THEN** the stderr artifact is content-matched and replaced with the count line
  (symmetric with stdout redaction)

#### Scenario: normal-command-output-passes-through

- **WHEN** command output does not match the env-dump shape (fewer than two KEY=VALUE
  lines, or fewer than half of non-empty lines match the pattern)
- **THEN** the output passes through unchanged (with credential scrubbing still applied)

#### Scenario: env-exit-code-is-preserved

- **WHEN** an env-dump is redacted
- **THEN** the exit code in the SandboxExecCapture is the actual exit code of the command