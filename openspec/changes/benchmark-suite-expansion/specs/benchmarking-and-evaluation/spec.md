## ADDED Requirements

### Requirement: Benchmark result artifact with standard metrics

Every benchmark run SHALL emit a result artifact recording per-class recall, false-positive rate, proof rate (found → proven), token cost per proven finding, and wall-clock, together with provenance (model, prompt hashes, config). Results SHALL be stored so runs are comparable across harness changes.

#### Scenario: Run emits comparable metrics

- **WHEN** `quarry benchmark local` completes on a known fixture set
- **THEN** the result artifact contains recall/FP/proof-rate/cost/wall-clock plus model, prompt-hash, and config provenance

#### Scenario: Two runs are diffable

- **WHEN** two benchmark runs are executed under different harness configs
- **THEN** their result artifacts can be compared field-by-field

### Requirement: Fixture breadth across every class

The local benchmark SHALL carry ground-truth fixtures and example targets covering every `VulnerabilityClass`, for both web and CLI targets, so per-class recall is measurable across the whole huntable surface.

#### Scenario: Class-coverage matrix is complete

- **WHEN** the benchmark fixture inventory is enumerated
- **THEN** every huntable `VulnerabilityClass` has at least one ground-truth fixture

### Requirement: Planted-regression target

The benchmark SHALL include a deliberately vulnerable target whose vulnerabilities are not published anywhere (the analog of Microsoft's StorageDrive interview driver), used to detect harness regressions without training-data contamination.

#### Scenario: Planted target detects a regression

- **WHEN** a harness change drops detection of a planted vulnerability
- **THEN** the benchmark reports the recall drop on the planted target

### Requirement: External benchmark adoption

Quarry SHALL adopt at least one external benchmark — CyberGym (the MDASH benchmark) or XBEN (Shannon's published targets) — with a runner and a recorded baseline, enabling comparability against published harnesses.

#### Scenario: External benchmark baseline is recorded

- **WHEN** an external benchmark is adopted
- **THEN** a runner exists and a baseline score with provenance is stored as an artifact
