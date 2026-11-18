## ADDED Requirements

### Requirement: Structured severity rationale on findings

Every `CandidateFinding` SHALL carry a non-optional `severity_rationale: SeverityRationale` field with three required text slots — `impact`, `exploitability`, `reachability` — and optional evidence pointers. Schema enforcement boundary: the three slots are required and an explicit `severity_rationale=null` is rejected with `ValidationError`; input lacking the key entirely receives the legacy backfill (next requirement).

#### Scenario: hunt_finding_carries_structured_rationale

- **WHEN** the hunt agent emits a candidate finding with severity "critical"
- **THEN** `severity_rationale.impact`, `.exploitability`, and `.reachability` are each non-empty

#### Scenario: finding_without_rationale_is_rejected_at_schema_boundary

- **WHEN** a `CandidateFinding` is constructed with an explicit `severity_rationale=null`
- **THEN** Pydantic raises a `ValidationError` rather than silently accepting it

#### Scenario: evidence_pointers_link_rationale_to_source_locations

- **WHEN** a rationale claim cites supporting evidence (e.g. "full database read at users.py:42")
- **THEN** the rationale slot carries `evidence_refs` indices into `evidence_path` or `source_refs`

### Requirement: Legacy backfill for pre-contract findings

Pre-contract findings persisted without `severity_rationale` SHALL deserialize without error. An absent key SHALL default to a `legacy=true` rationale whose slots read "No structured severity rationale from pre-contract scan."

#### Scenario: pre_contract_finding_loads_with_legacy_marker

- **WHEN** a `CandidateFinding` JSON blob lacks `severity_rationale`
- **THEN** deserialization produces a rationale with `legacy=true` and disclosure text in all three slots

#### Scenario: legacy_marker_not_auto_cleared

- **WHEN** new fields are added to a finding that already carries `legacy=true`
- **THEN** the `legacy` flag remains `true` — it is set once and never auto-cleared

### Requirement: All finding-emitting roles populate the contract

Every `CandidateFinding` construction site — the hunt parser, the exploitation loop, diff-scan candidate emission, agentic candidate sources, and the secrets plugin — SHALL produce a `severity_rationale`. The model-output-fed parser (`_parse_finding`) SHALL map model rationale fields directly and SHALL flag missing slots with `model_omitted=true` rather than fabricating values.

#### Scenario: model_output_with_rationale_mapped_directly

- **WHEN** a hunt model outputs `impact`, `exploitability`, and `reachability` in its finding JSON
- **THEN** `_parse_finding` maps them into `severity_rationale` with `model_omitted=false`

#### Scenario: model_output_without_rationale_flagged

- **WHEN** a hunt model emits a finding with no `severity_rationale` fields
- **THEN** `_parse_finding` still produces a `CandidateFinding` with `model_omitted=true` and disclosure text

#### Scenario: validator_boundary_excludes_rationale

- **WHEN** a `ValidatorClaim` is constructed from a `CandidateFinding`
- **THEN** `severity_rationale` is excluded per ADR-021 independence boundary

### Requirement: Report renders structured severity sections

The report SHALL render Impact, Exploitability, and Reachability subsections per final finding, sourced from `severity_rationale`. Evidence pointers SHALL render as links. `legacy` or `model_omitted` slots SHALL render untruncated disclosure text rather than fabricating justification.

#### Scenario: report_renders_rationale_for_final_finding

- **WHEN** a final finding carries `severity_rationale.impact=full_db_access`
- **THEN** the report includes an Impact subsection with that text and any evidence links

#### Scenario: legacy_finding_renders_honest_disclosure

- **WHEN** a finding carries `severity_rationale.legacy=true`
- **THEN** the report renders the standard disclosure text without fabricating rationale

#### Scenario: model_omitted_rationale_renders_disclosure

- **WHEN** a finding carries `severity_rationale.model_omitted=true`
- **THEN** the report renders "Model did not provide structured severity rationale"

### Requirement: Rationale survives candidate-to-final promotion

`severity_rationale` SHALL be copied verbatim from `CandidateFinding` to `FinalFinding` during promotion, so the contract is preserved through validation and calibration.

#### Scenario: promoted_finding_keeps_rationale

- **WHEN** a `CandidateFinding.severity_rationale.impact` is "server admin escalation" and it is promoted
- **THEN** the `FinalFinding.severity_rationale.impact` is unchanged