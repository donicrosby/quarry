## ADDED Requirements

### Requirement: SARIF 2.1.0 export as a FindingSink

Quarry SHALL provide a FindingSink that serializes findings as a SARIF v2.1.0 log file
per the OASIS SARIF specification. Severity SHALL map to SARIF `result.level`, source
locations SHALL populate `result.locations[].physicalLocation`, and finding fingerprints
SHALL populate `result.partialFingerprints`.

#### Scenario: sarif-export-produces-valid-sarif-log

- **WHEN** a scan completes and findings are delivered through the SARIF sink
- **THEN** the output artifact is a valid SARIF v2.1.0 JSON document with `runs[0].results[]` populated

#### Scenario: severity-maps-to-sarif-level

- **WHEN** a finding has severity `critical`
- **THEN** the SARIF result level is `error`; severity `high` maps to `error`; `medium` to `warning`; `low` and `info` to `note`

#### Scenario: source-location-populates-physicallocation

- **WHEN** a finding carries a source-location file path and line range
- **THEN** the SARIF result includes `locations[0].physicalLocation` with `artifactLocation.uri` and `region.startLine`

#### Scenario: fingerprint-populates-partialfingerprints

- **WHEN** a finding has a stable fingerprint
- **THEN** the SARIF result carries `partialFingerprints.quarryFingerprint` set to that fingerprint value

#### Scenario: dry-run-sarif-sink-writes-no-file

- **WHEN** the SARIF sink is invoked with dry-run enabled
- **THEN** it produces a dry-run `IntegrationRun` record and writes no SARIF file to disk

#### Scenario: empty-scan-produces-valid-empty-sarif

- **WHEN** a scan completes with zero findings
- **THEN** the SARIF log is still valid (empty `results[]` array, `tool.driver` metadata present)

### Requirement: Reusable GitHub Action for Quarry SARIF scanning

Quarry SHALL ship a reusable GitHub Action workflow that runs a Quarry scan against the
calling repository, invokes the SARIF sink, and uploads the SARIF artifact via
`github/codeql-action/upload-sarif`. The action SHALL accept a Quarry configuration
reference and an optional severity threshold as inputs.

#### Scenario: github-action-runs-quarry-and-uploads-sarif

- **WHEN** the reusable workflow is invoked from a GitHub Actions job with a valid quarry config
- **THEN** Quarry runs a scan, produces a SARIF artifact, and uploads it to GitHub Code Scanning

#### Scenario: github-action-respects-severity-threshold

- **WHEN** the action input `severity_threshold` is set to `high`
- **THEN** only findings at or above `high` severity appear in the uploaded SARIF results

#### Scenario: github-action-surfaces-scan-failure

- **WHEN** the Quarry scan fails (non-zero exit)
- **THEN** the workflow job fails and no SARIF upload is attempted

### Requirement: GitLab CI/CD component for Quarry SAST scanning

Quarry SHALL ship a GitLab CI/CD component that runs a Quarry scan in a GitLab pipeline,
produces a SARIF artifact, and publishes it as a GitLab SAST report artifact. The
component SHALL accept a Quarry configuration reference and an optional severity
threshold as inputs, mirroring the GitHub Action contract.

#### Scenario: gitlab-component-runs-quarry-and-publishes-sarif

- **WHEN** the component is included in a GitLab pipeline with a valid quarry config
- **THEN** Quarry runs a scan, produces a SARIF artifact, and publishes it as a GitLab SAST report

#### Scenario: gitlab-component-respects-severity-threshold

- **WHEN** the component input `severity_threshold` is set to `high`
- **THEN** only findings at or above `high` severity appear in the SARIF report artifact

#### Scenario: gitlab-component-surfaces-scan-failure

- **WHEN** the Quarry scan fails (non-zero exit)
- **THEN** the pipeline job fails and no SAST artifact is produced