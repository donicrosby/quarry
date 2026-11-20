## ADDED Requirements

### Requirement: Planted-regression example target

The project SHALL ship one deliberately vulnerable example target whose vulnerabilities are not published anywhere, used as a regression detector. The target SHALL carry 3–5 known vulnerabilities across at least two `VulnerabilityClass` values, a ground-truth manifest, and SHALL be launchable with `quarry target start`.

#### Scenario: planted_target_is_launchable

- **WHEN** `quarry target start` runs against the planted target's repo
- **THEN** the target launches and reports ready within the timeout

#### Scenario: planted_target_ground_truth_scannable

- **WHEN** the local benchmark runs against the planted target with its ground-truth manifest
- **THEN** recall, FP rate, and proof rate are computed per the standard metric schema

#### Scenario: planted_target_vulns_vary_in_class

- **WHEN** the planted target's ground-truth manifest is enumerated
- **THEN** at least two distinct VulnerabilityClass values are represented
