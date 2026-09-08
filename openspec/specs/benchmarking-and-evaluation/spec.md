# benchmarking-and-evaluation Specification

## Purpose

Claims about how well Quarry finds vulnerabilities must be earned by running it. A local
benchmark scores against bundled ground truth as a regression harness, and an external
benchmark is run under strict cost and honesty guardrails. Numbers are never projected,
extrapolated from dry runs, or claimed without a real run behind them. The external benchmark is CyberGym.

## Requirements

### Requirement: Local benchmark as a regression harness

The project SHALL provide a local benchmark that scores scans against bundled ground truth
and reports precision/recall-style metrics, usable as a regression check. It SHALL NOT be
presented as an external-validity claim.

#### Scenario: Local benchmark reports metrics

- **WHEN** the local benchmark runs
- **THEN** it reports its metrics against the bundled ground truth

### Requirement: External benchmark cost guardrails

An external benchmark run SHALL always set a cost cap, SHALL run a small dry run before a
full run, and SHALL be treated as a post-release activity, not a release gate.

#### Scenario: External run without a cost cap is refused

- **WHEN** an external benchmark is launched without a configured cost cap
- **THEN** it is refused

### Requirement: Ablation attribution

Attributing a metric change to a pipeline stage SHALL require with-and-without runs; a
stage's contribution SHALL NOT be asserted without an ablation.

#### Scenario: Stage claim requires an ablation

- **WHEN** a claim is made that a stage improves precision
- **THEN** it is backed by a with/without ablation run

### Requirement: Honesty rules for reported numbers

Reported benchmark numbers SHALL come from actual runs; results SHALL NOT be projected,
extrapolated from a dry run, or claimed as matching a reference score without running.

#### Scenario: No number without a run

- **WHEN** a benchmark result would be published
- **THEN** it corresponds to a completed real run rather than an estimate
