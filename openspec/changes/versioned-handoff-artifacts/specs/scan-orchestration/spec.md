## ADDED Requirements

### Requirement: Cold-start resume from handoff artifacts

The scan workflow SHALL support resuming a hunt from handoff artifacts alone. When
a scan enters the HUNT stage and detects a prior hunt round that produced handoff
artifacts but did not reach completion, it SHALL load the latest ArchitectureDoc,
CoverageLedger, and HuntHandoff from the artifact store and resume without
re-covering completed scope units or re-emitting findings that were already produced. Artifact lookup SHALL be scoped to the current `scan_id`.

#### Scenario: cold_start_resume_from_artifacts

- **WHEN** a scan workflow resumes after the worker was killed mid-hunt and the
  last successful stage checkpoint is RECON (hunt produced artifacts but did not
  checkpoint completion)
- **THEN** the workflow loads the latest handoff artifacts, identifies covered
  units and existing findings, and launches only the pending hunt tasks

#### Scenario: cold_start_respects_covered_units

- **WHEN** a hunt resumes from handoff artifacts and the HuntHandoff lists scope
  units already covered
- **THEN** no hunter task is emitted for those units

#### Scenario: cold_start_preserves_open_hypotheses

- **WHEN** a hunt resumes from a HuntHandoff that records open hypotheses
- **THEN** those hypotheses are available to the resumed hunt agents as context

#### Scenario: findings_recorded_before_interruption_survive_resume

- **WHEN** a hunt round recorded candidate findings before the workflow was killed
- **THEN** after cold-start resume those findings remain present and none are silently dropped

#### Scenario: clean_start_when_no_prior_artifacts

- **WHEN** a scan enters HUNT for the first time with no existing handoff artifacts
- **THEN** the hunt starts from scratch with all tasks emitted from the
  ArchitectureDoc as normal