## ADDED Requirements

### Requirement: Ordered sink-first evidence path on findings

The finding schema SHALL represent evidence locations as an ordered list whose
first element is the sink (the flaw's primary location), followed by the steps
back toward the source. Each element SHALL be a repo-relative `path:line`
locator. The ordering SHALL be part of the contract downstream stages rely on
for dedup and correlation.

#### Scenario: Order is preserved end to end

- **WHEN** a finding with an ordered evidence path is persisted and re-read
- **THEN** the sink remains the first element and the order is unchanged

### Requirement: Calibrated severity fields

The finding schema SHALL carry both the raw severity produced by the hunter and
a calibrated severity and priority produced by calibration, plus the identifiers
of any calibration rules that fired. The raw severity SHALL NOT be overwritten by
calibration.

#### Scenario: Both severities are present after calibration

- **WHEN** a finding has been calibrated
- **THEN** it exposes its raw severity, its calibrated severity/priority, and the
  firing rule identifiers

### Requirement: Fail-safe verdict defaults

Verdict-producing stages SHALL bias toward retaining a finding when a judgement
cannot be completed. A deployment-intent judgement SHALL default to "production"
unless every production-signal check is false. A viability or re-verification
judgement that cannot be completed because a cited file is missing or a cited
line is out of range SHALL default to the conservative "retain" verdict and
SHALL NOT mark the finding as discardable on that basis.

#### Scenario: Intent defaults to production under uncertainty

- **WHEN** any production-signal check is true or unknown
- **THEN** the deployment intent is recorded as production

#### Scenario: Missing file does not silently drop a finding

- **WHEN** a re-verification stage cannot read a cited file or the cited line is
  out of range
- **THEN** the finding is retained under the conservative default verdict rather
  than discarded
