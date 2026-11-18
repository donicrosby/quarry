## MODIFIED Requirements

### Requirement: Egress pinning for live proof

When a live proof requires network access it SHALL be governed by a destination-set policy that allows only the authorized destinations. A compromised sandbox SHALL NOT be able to reach any destination outside the policy's declared sets.

#### Scenario: Sandbox reaches only the authorized target

- **WHEN** live-proof network access is enabled with a destination-set policy
- **THEN** egress is limited to the destinations declared in the policy and no other host

#### Scenario: Empty policy permits no egress

- **WHEN** the destination-set policy has zero destination sets declared
- **THEN** no network egress is available

## ADDED Requirements

### Requirement: Per-destination-set egress policy

Sandbox egress SHALL be governed by a policy of named destination sets, not a single target endpoint. Each destination set SHALL declare allowed domains and/or IPs for one category of outbound traffic; any destination not in any set SHALL be denied.

#### Scenario: Multi-destination policy reaches canary and target

- **WHEN** a policy has destination sets for `target-host` and `canary-listener`
- **THEN** sandboxed code can reach both sets' declared destinations and no other host

#### Scenario: Destination not in any set is blocked

- **WHEN** sandboxed code attempts to reach a destination not declared in any destination set
- **THEN** the connection is refused at the sandbox tier

### Requirement: DNS rebinding protection

Every destination domain in a destination set SHALL be resolved to IP addresses once at policy construction. Re-resolution during sandbox execution SHALL be rejected; only the initially-resolved IPs SHALL be reachable.

#### Scenario: Domain re-resolution is rejected

- **WHEN** sandboxed code causes a DNS re-resolution of a policy domain mid-execution
- **THEN** the re-resolution is not honored and only the initially-resolved IPs remain reachable

#### Scenario: Policy construction resolves once

- **WHEN** a destination-set policy is built at scan start
- **THEN** all domain entries are resolved to IPs exactly once and the resolution is frozen for the policy lifetime

### Requirement: Tier-level policy enforcement

Every sandbox tier SHALL enforce destination-set policies at its isolation boundary. Tier 2 (ContainerSandbox) SHALL restrict network access to the union of resolved destination-set IPs. Tier 3 (K8sJobSandbox) SHALL enforce via NetworkPolicy with egress rules matching the resolved destination sets.

#### Scenario: ContainerSandbox enforces per-destination-set policy

- **WHEN** ContainerSandbox runs with a destination-set policy
- **THEN** the container's network namespace permits only the resolved destination IPs

#### Scenario: K8sJobSandbox enforces via NetworkPolicy

- **WHEN** K8sJobSandbox runs with a destination-set policy
- **THEN** a NetworkPolicy is applied that permits egress only to the resolved destination IPs