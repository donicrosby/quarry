## ADDED Requirements

### Requirement: Destination-set-aware proof configuration

The prove stage SHALL configure the sandbox with a destination-set policy derived from the scan's egress policy, scoped to the destinations the proof scenario requires. A proof that needs browser access SHALL receive the `browser-target` set; a proof that needs SSRF canary detection SHALL receive the `canary-listener` set.

#### Scenario: Destination sets are scoped to proof needs

- **WHEN** a proof scenario requires browser-automation proof
- **THEN** the sandbox is configured with the `browser-target` destination set only

#### Scenario: Proof without live egress receives no destination sets

- **WHEN** a proof scenario requires no live network access
- **THEN** the sandbox receives an empty destination-set policy and has no egress