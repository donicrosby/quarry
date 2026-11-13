## ADDED Requirements

### Requirement: Replay a single agentic stage against prior scan state

The harness SHALL invoke any one agentic activity (hunt, gapfill, validate,
prove, trace, or a recon sub-activity) directly — outside the Temporal
workflow — using inputs reconstructed from a prior scan's persisted state, so a
prompt or logic change can be evaluated against realistic state without
re-running the pipeline.

#### Scenario: Replay validate against a real candidate

- **WHEN** `replay validate` is invoked with a prior scan id and repo path
- **THEN** the validate activity runs once against a candidate finding loaded
  from that scan's DB, using the current code and prompt templates, and its
  structured verdict is printed

#### Scenario: Replay hunt against a prior task

- **WHEN** `replay hunt` is invoked with a prior scan id and repo path
- **THEN** the hunt activity runs once against an agent task reconstructed from
  that scan's persisted state (including its KB reference when present), and
  the produced findings/gaps are printed

### Requirement: Replay reconstructs inputs from persisted state and fails loudly

For each stage, the harness SHALL resolve the activity's call arguments from
the prior scan's DB and artifact store (candidate findings, agent tasks, KB
artifacts, repo path, panel JSON, budget caps). When a required input cannot be
reconstructed from the scan's persisted state, the harness SHALL fail with an
explicit error naming the missing input rather than fabricating a fallback.

#### Scenario: Missing input is an explicit error

- **WHEN** a replay is requested for a scan that predates a required persisted
  input (e.g. no KB root-index key was recorded)
- **THEN** the harness exits non-zero naming the missing input and does not
  invoke the activity

### Requirement: Replay routes models exactly as a real scan

Replay SHALL resolve the panel via the same `load_quarry_config` +
`resolve_panel` path as a real scan, so model traffic goes through the LiteLLM
proxy and the configured tier — never direct to a provider and never silently
to the all-mock default panel. An explicit `--mock` flag SHALL select the mock
panel for zero-cost structural checks, and the chosen panel SHALL be printed in
the output header.

#### Scenario: Replay hits the configured proxy panel

- **WHEN** a replay runs without `--mock` under a configured panel
- **THEN** model invocations route through the LiteLLM proxy with the
  configured model for that role, and the panel name is printed in the output

#### Scenario: Mock mode is explicit and labeled

- **WHEN** a replay runs with `--mock`
- **THEN** no network model call is made, and the output header identifies the
  result as mock

### Requirement: Replay is read-only and replay-tagged

A replay SHALL NOT mutate the scan's persisted state (scan record, candidates,
finals, events, artifacts). Model invocations made during a replay SHALL be
recorded with a marker distinguishing them from scan invocations so replay
spend is attributable and does not pollute scan provenance.

#### Scenario: Replay leaves the scan record untouched

- **WHEN** a replay completes against a scan's DB
- **THEN** the scan's status, findings, and event log are unchanged, and any
  invocation recorded carries the replay marker

### Requirement: Each stage has a mock-panel golden replay test

Every supported stage SHALL have a test that drives the harness end-to-end
under the mock panel — input resolves, the activity runs, and the result is
structurally valid — with no network and no Temporal server.

#### Scenario: Mock replay test proves the harness wiring

- **WHEN** the replay test suite runs
- **THEN** each stage's harness path resolves inputs and produces a
  structurally valid result under the mock panel without external services
