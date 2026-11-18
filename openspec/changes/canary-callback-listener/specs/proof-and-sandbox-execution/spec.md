## ADDED Requirements

### Requirement: Canary callback proof for SSRF and XXE findings

The prove stage SHALL detect SSRF and XXE exploitation via an out-of-band canary callback rather than HTTP response inspection. When a finding's vulnerability class is SSRF or XXE, the workflow SHALL start a canary listener co-located with the sandbox, inject the canary URL into the prove agent's prompt, and collect callbacks after sandbox execution.

#### Scenario: SSRF finding triggers canary lifecycle

- **WHEN** a finding with `vuln_class=SSRF` enters the prove stage and live target access is authorized
- **THEN** the workflow generates a unique canary token, constructs a canary URL containing the token, passes it to the prove agent via `canary_url` in the prompt template, and dispatches `sandbox-exec` with `canary_token` set

#### Scenario: Non-SSRF/XXE finding skips canary overhead

- **WHEN** a finding with a vulnerability class other than SSRF or XXE enters the prove stage
- **THEN** no canary listener is started, no `canary_url` is injected, and `sandbox-exec` runs with `canary_token=None`

#### Scenario: Canary callback corroborates SSRF

- **WHEN** the sandbox executes a crafted SSRF payload and the target fetches the canary URL
- **THEN** the listener logs a request whose path contains the probe token, and the verdict evaluator returns `corroborated`

#### Scenario: No callback leaves verdict unchanged

- **WHEN** the sandbox executes but no request reaches the canary listener
- **THEN** the canary evaluator returns `not_corroborated` and the proving attempt continues to the next attempt (capped at `PROVE_MAX_ATTEMPTS`)

### Requirement: Canary URL injection into the prove agent prompt

The workflow SHALL inject the canary URL into the prove agent's prompt as a template variable `{{ canary_url }}` when the finding class is SSRF or XXE. The prompt template SHALL instruct the agent to craft SSRF payloads that cause the target to fetch the canary URL, and XXE payloads that reference the canary URL as an external entity.

#### Scenario: Prove agent receives canary URL for SSRF

- **WHEN** the prove agent is invoked for an SSRF finding with a live target
- **THEN** the prompt contains `canary_url` set to `http://<host>:<port>/<token>` and instructs the agent to propose sandbox commands whose target fetches that URL

#### Scenario: Prove agent prompt omits canary URL for non-OOB classes

- **WHEN** the prove agent is invoked for a finding whose class is not SSRF or XXE
- **THEN** the prompt does not contain the `canary_url` variable and carries no canary-related instructions

### Requirement: Canary evidence collection and verdict evaluation

The `sandbox-exec` activity SHALL return collected canary callbacks in `SandboxExecCapture.canary_callbacks`. A new `canary_evaluator` registered for `SSRF` and `XXE` vulnerability classes SHALL inspect the callbacks and return `corroborated` when at least one callback's request path contains the probe token. The `prove_outcome_from_captures` function SHALL consult canary evidence alongside exec and HTTP captures.

#### Scenario: Callback with matching token flips verdict

- **WHEN** `SandboxExecCapture.canary_callbacks` contains at least one entry whose `path` field includes the probe token
- **THEN** `canary_evaluator` returns `corroborated` regardless of the sandbox command's exit code

#### Scenario: Callbacks present but none match the token

- **WHEN** `canary_callbacks` is non-empty but no entry's path contains the probe token
- **THEN** `canary_evaluator` returns `not_corroborated` — noise callbacks without the token do not prove exploitation

#### Scenario: No callbacks collected

- **WHEN** `canary_callbacks` is empty and the sandbox executed normally
- **THEN** `canary_evaluator` returns `not_corroborated` and the attempt loop may retry with a fresh token