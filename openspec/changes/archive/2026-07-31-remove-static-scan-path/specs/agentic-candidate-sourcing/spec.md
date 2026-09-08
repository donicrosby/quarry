## ADDED Requirements

### Requirement: Candidate findings originate only from agentic sources

Candidate findings SHALL be produced only by agentic activities — the hunt loop and
its coverage-driven / reachability-feedback re-queue edges. The scan pipeline SHALL
NOT contain a static scanner stage or a static attack-surface enumeration stage as a
candidate source.

The secrets scanner (`scan_repo_for_secrets`) is exempt as a **diff-scan** tool: it
remains available to the commit-diff workflow and is not a candidate source in the
main agentic pipeline.

#### Scenario: Main scan produces candidates only from hunt

- **WHEN** a `RunScanWorkflow` executes
- **THEN** every candidate finding traces to a hunt (or hunt re-queue) agent task
- **AND** no candidate is produced by a static route-extraction or static vuln-class
  scanner

#### Scenario: Orphaned static producers are gone

- **WHEN** the codebase is inspected for the removed producers
- **THEN** `attack_surface` route extraction, the static `idor` and
  `command_injection` scanners, and the hand-coded per-class dynamic validators are
  absent, along with their worker/server registrations

### Requirement: No orphaned static UI or API surface

The removal SHALL leave no orphaned static-path surface that renders empty or returns
dead data: the attack-surface TUI screen and route-table widget, the
`GET /scans/{id}/attack_surface` API route, the `attack_surface_items` persistence
table, and the report's attack-surface section SHALL be removed.

#### Scenario: Attack-surface API route is gone

- **WHEN** a client requests `GET /scans/{id}/attack_surface`
- **THEN** the route does not exist (the server exposes no attack-surface endpoint)

#### Scenario: Report omits the attack-surface section

- **WHEN** a scan report is rendered
- **THEN** it contains no attack-surface section

### Requirement: Coverage accounting names agentic units

Coverage accounting SHALL name the units it actually counts. The
`CoverageLedger`/`CoverageGap` fields that previously referenced "attack surface
items" SHALL be renamed to reflect agentic task / scope-unit counting, and the report
SHALL render the renamed fields.

#### Scenario: Ledger reports agentic-unit coverage

- **WHEN** a coverage ledger is built for an agentic scan
- **THEN** its scanned/total counts are named for agentic units (not attack-surface
  items)
- **AND** the rendered report's Coverage section uses the renamed labels
