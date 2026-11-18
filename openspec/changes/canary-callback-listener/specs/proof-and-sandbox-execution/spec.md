## ADDED Requirements

### Requirement: Destination-set configuration with canary sidecar activation

The prove stage SHALL scope a destination-set policy to the proof scenario's needs. Browser proof SHALL receive `browser-target`. SSRF/XXE canary detection SHALL activate a sidecar listener via `canary_token` on the `sandbox-exec` input; the canary is infrastructure, not a destination set. This supersedes D1's `canary-listener` destination-set model.

#### Scenario: Destination sets are scoped to proof needs

- **WHEN** a proof scenario requires browser-automation proof
- **THEN** the sandbox is configured with the `browser-target` destination set only

#### Scenario: Proof without live egress receives no destination sets

- **WHEN** a proof scenario requires no live network access
- **THEN** the sandbox receives an empty destination-set policy and has no egress

#### Scenario: SSRF proof activates canary sidecar, not destination set

- **WHEN** a proof scenario requires SSRF or XXE canary detection
- **THEN** the `sandbox-exec` activity receives `canary_token` and the sandbox-scoped egress policy does NOT include a `canary-listener` destination set

#### Scenario: Live-target egress is scoped to the container tier

- **WHEN** a prove requires live target egress (a non-empty `target-host` set)
- **THEN** it runs on Tier 2 (`ContainerSandbox`); the Tier-1 (`LocalSubprocessSandbox`) prove path receives an empty policy and never raises `EgressPolicyError`

### Requirement: Canary callback proof for SSRF and XXE findings

The prove stage SHALL detect SSRF and XXE via an out-of-band canary callback. When `vuln_class` is SSRF or XXE, the workflow SHALL activate a canary listener, inject a canary URL instruction, and evaluate callbacks after sandbox execution. Corroboration SHALL require a callback `source_ip` matching a resolved target IP and is Tier-2-only.

#### Scenario: SSRF finding triggers canary lifecycle

- **WHEN** a finding with `vuln_class=SSRF` enters the prove stage
- **THEN** the workflow generates a deterministic canary token, passes it to `sandbox-exec` via `canary_token`, and injects a canary URL instruction into the prove prompt

#### Scenario: Non-SSRF/XXE finding skips canary overhead

- **WHEN** a finding with a vulnerability class other than SSRF or XXE enters the prove stage
- **THEN** no canary listener is started, no canary URL instruction is injected, and `sandbox-exec` runs with `canary_token=None`

#### Scenario: Tier-2 callback from authorized target IP corroborates

- **WHEN** in Tier 2 a canary callback arrives whose `source_ip` matches a resolved target IP and whose path contains the probe token
- **THEN** the prove outcome returns `corroborated`

#### Scenario: Tier-1 callback is logged but never corroborates

- **WHEN** in Tier 1 a canary callback arrives, including one whose path contains the token
- **THEN** the callback is logged but the prove outcome does NOT return `corroborated` — a loopback listener cannot distinguish target from sandbox

#### Scenario: Callback from sandbox IP does not corroborate

- **WHEN** a canary callback arrives from the sandbox's own address space (the sandbox container's IP in Tier 2) even though the path contains the token
- **THEN** the callback is logged but the prove outcome does NOT return `corroborated`

#### Scenario: No callback leaves verdict unchanged

- **WHEN** the sandbox executes but no request reaches the canary listener
- **THEN** the prove outcome returns `not_corroborated` and the attempt loop may retry with a fresh token

### Requirement: Canary URL injection into the prove agent prompt

The workflow SHALL inject a canary URL instruction into the prove prompt when the finding class is SSRF or XXE. The prompt SHALL instruct the agent to reference the `QUARRY_CANARY_URL` environment variable when crafting payloads. The `sandbox-exec` activity SHALL set `QUARRY_CANARY_URL` to the listener's tier-specific address before executing sandbox commands.

#### Scenario: Prove agent receives canary URL instruction for SSRF

- **WHEN** the prove agent is invoked for an SSRF or XXE finding
- **THEN** the prompt instructs the agent to use `$QUARRY_CANARY_URL` as the callback target, and the activity sets that variable to the listener's bound address

#### Scenario: Prove agent prompt omits canary instruction for non-OOB classes

- **WHEN** the prove agent is invoked for a finding whose class is not SSRF or XXE
- **THEN** the prompt does not contain the canary URL instruction and carries no canary-related guidance

### Requirement: Canary evidence evaluation in prove outcome

`prove_outcome_from_captures` SHALL consult canary callbacks alongside exec and HTTP captures. A callback whose `source_ip` matches a resolved target IP returned on `SandboxExecCapture.resolved_target_ips` and whose path contains the token SHALL yield `corroborated`. Sandbox-originated callbacks SHALL be logged but NOT corroborate. Evaluation is direct integration in the prove-stage path, not a verdict-evaluator registry entry; `ssrf_evaluator` SHALL remain unchanged.

#### Scenario: Callback from target IP with matching token yields corroborated

- **WHEN** `SandboxExecCapture.canary_callbacks` contains a callback whose `source_ip` matches an IP in `resolved_target_ips` and whose `path` contains the token
- **THEN** `prove_outcome_from_captures` returns `corroborated`

#### Scenario: Callback from sandbox IP with token is ignored

- **WHEN** `canary_callbacks` contains a callback whose `source_ip` is not in `resolved_target_ips`, even if the path contains the token
- **THEN** `prove_outcome_from_captures` ignores that callback and does NOT return `corroborated` from it

#### Scenario: Callbacks present but none match the token

- **WHEN** `canary_callbacks` is non-empty but no entry's path contains the probe token
- **THEN** `prove_outcome_from_captures` does not return `corroborated` from canary evidence

#### Scenario: No callbacks collected

- **WHEN** `canary_callbacks` is empty and the sandbox executed normally
- **THEN** `prove_outcome_from_captures` does not return `corroborated` from canary evidence and the attempt loop may retry
