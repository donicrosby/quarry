## ADDED Requirements

### Requirement: Benchmark result artifact with standard metrics

Every benchmark run SHALL emit a result artifact recording per-class recall, false-positive rate, proof rate (found → proven), token cost per proven finding, and wall-clock, together with provenance (model, prompt hashes, config). Results SHALL be stored so runs are comparable across harness changes.

#### Scenario: run_emits_comparable_metrics

- **WHEN** `quarry benchmark local` completes on a known fixture set
- **THEN** the result artifact contains recall/FP/proof-rate/cost/wall-clock plus model, prompt-hash, and config provenance

#### Scenario: two_runs_are_diffable

- **WHEN** two benchmark runs are executed under different harness configs
- **THEN** their result artifacts can be compared field-by-field

### Requirement: Local benchmark emits the result artifact schema

The `quarry benchmark local` command SHALL emit a `BenchmarkRunResult` artifact (schema at src/quarry/benchmark_artifacts.py:93) with `RunProvenance` and `BenchmarkMetrics`, not only the lightweight `compare()` summary. The artifact SHALL be persisted so local runs are comparable field-by-field.

#### Scenario: local_benchmark_writes_artifact

- **WHEN** `quarry benchmark local --repo <path> --ground-truth <path>` completes
- **THEN** a BenchmarkRunResult artifact is written with provenance (model, prompt hashes, config, harness SHA) and metrics (per-class recall, FP rate, proof rate, cost, wall-clock)

#### Scenario: artifact_carries_provenance

- **WHEN** a local benchmark artifact is read back
- **THEN** its RunProvenance fields (models, prompt_hashes, config, harness_sha) are populated, never default or empty

### Requirement: Fixture breadth — huntable vs benchmarkable

The benchmark fixture inventory SHALL differentiate VulnerabilityClass values that are huntable (have a prompt template) from those that are benchmarkable (have ground-truth fixtures). SHALL NOT falsely claim class coverage where only a template exists but no ground truth can score it.

#### Scenario: inventory_enumerates_every_class

- **WHEN** the benchmark fixture inventory is enumerated
- **THEN** every VulnerabilityClass member is listed with its hunt-template status and ground-truth fixture count

#### Scenario: benchmarkable_classes_have_ground_truth

- **WHEN** a VulnerabilityClass is reported as benchmarkable
- **THEN** at least one ground-truth fixture exists for that class, in at least one target language (web or CLI)

### Requirement: Planted-regression target

The benchmark SHALL include a deliberately vulnerable target with 3–5 known vulnerabilities never published anywhere (the analog of Microsoft's StorageDrive interview driver), in one language, with a ground-truth manifest recording class, location, and expected proof type for each vuln.

#### Scenario: planted_target_detects_a_regression

- **WHEN** a harness change drops detection of a planted vulnerability
- **THEN** the benchmark reports the recall drop on the planted target, naming the specific vuln class and file that regressed

#### Scenario: planted_target_vulns_unpublished

- **WHEN** the planted target's source and manifest are inspected
- **THEN** none of its vulnerability descriptions or locations appear in public training corpora, benchmark datasets, or the example targets

### Requirement: External benchmark adoption

Quarry SHALL adopt at least one external benchmark — CyberGym (the MDASH benchmark) or XBEN (Shannon's published targets) — with a runner and a recorded baseline, enabling comparability against published harnesses.

#### Scenario: external_benchmark_baseline_is_recorded

- **WHEN** an external benchmark is adopted
- **THEN** a runner exists and a baseline score with provenance is stored as an artifact

#### Scenario: cybergym_runner_is_wired

- **WHEN** `quarry benchmark cybergym --manifest <path> --subset official10 --level level1` is invoked
- **THEN** the CyberGym runner materializes tasks, reproduces with the agent, verifies against docker images, and emits a BenchmarkRunResult with TaskOutcome records
