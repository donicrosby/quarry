# reporting-and-replay Specification

## Purpose

The report is the product's output: a deterministic Markdown document of findings,
coverage, provenance, and model cost that reads the same given the same inputs. Because
state is fully persisted, a report can be re-rendered later without re-running the scan or
making any model calls, which is also how a scan is audited and replayed.

## Requirements

### Requirement: Deterministic report rendering

Report rendering SHALL produce identical output from identical stored inputs (except
explicit timestamps), with findings ordered by a stable sort (severity, class,
fingerprint).

#### Scenario: Same inputs render the same report

- **WHEN** a report is rendered twice from the same stored state
- **THEN** the output is identical apart from explicit timestamps

### Requirement: Report contents

The report SHALL include final findings with provenance, a coverage summary, a model-cost
summary, and the loop stop reason. Findings needing proof SHALL be retained and surfaced
rather than dropped.

#### Scenario: Needs-proof findings are shown

- **WHEN** a scan ends with findings still needing proof
- **THEN** the report surfaces them rather than omitting them

#### Scenario: Coverage is reported honestly

- **WHEN** parts of the target were skipped
- **THEN** the report's coverage summary reflects the skipped units

### Requirement: Replay makes no model calls or external effects

A report SHALL be re-renderable from stored state without re-running the scan, and replay
SHALL make no new model calls and fire no integrations.

#### Scenario: Replay re-renders offline

- **WHEN** a scan is replayed to re-render its report
- **THEN** no model call is made and no integration is dispatched

### Requirement: Rerun modes are explicit

Rerun behavior SHALL be selectable among defined modes (e.g. fresh, replay), and a replay
mode SHALL be distinguishable from a fresh scan.

#### Scenario: Replay mode is honored

- **WHEN** rerun is requested in replay mode
- **THEN** the existing state is re-rendered rather than a new scan started
