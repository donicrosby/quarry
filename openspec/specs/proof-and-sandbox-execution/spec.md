# proof-and-sandbox-execution Specification

## Purpose

A finding that needs proof is confirmed by producing a safe local proof-of-concept in a
sandbox, not by asserting it. Only the prove role may execute in the sandbox, each attempt
runs in its own scratch directory that is always cleaned up, and attempts are capped so a
proof cannot loop forever. The result is a proof artifact attached to the finding.

## Requirements

### Requirement: Proof generation for needs-proof findings

The prove stage SHALL run for findings carrying the `needs_proof` status, generating a
proof-of-concept and attaching a proof artifact to the finding on success.

#### Scenario: Proof artifact is attached

- **WHEN** a proof succeeds for a needs-proof finding
- **THEN** a proof artifact reference is attached to the finding

### Requirement: Only the prove role executes in the sandbox

Sandboxed execution SHALL be available only to the prove role; other roles SHALL NOT be
able to run in the sandbox.

#### Scenario: Non-prove role cannot execute

- **WHEN** a role other than prove attempts sandboxed execution
- **THEN** the tool runner refuses the call

### Requirement: Isolated, always-cleaned scratch

Each proof attempt SHALL run in a per-task scratch directory created and removed via
try/finally, so a failed attempt does not leave residue or leak into another task.

#### Scenario: Scratch is removed on failure

- **WHEN** a proof attempt raises
- **THEN** its scratch directory is still removed

### Requirement: Bounded attempts

Proof attempts SHALL be capped (at most three per finding) in code, so proving terminates
deterministically.

#### Scenario: Attempts stop at the cap

- **WHEN** proof attempts reach the cap without success
- **THEN** no further attempt runs and the finding is recorded as unproven
