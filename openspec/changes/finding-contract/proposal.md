# Change: finding-contract

## Why

QUARRY's `CandidateFinding` carries a bare `Severity` enum and optional free-text
`reasoning`, but there is no structured severity rationale that decomposes a
finding into **impact**, **exploitability**, and **reachability** with explicit
evidence pointers. ADR-026 rule 4 declares "findings are data, not prose," yet
the current severity assignment is a single label with no auditable decomposition.
The report renders `finding.severity.value` as a label (reporting.py:113) —
consumers like SARIF exporters, CI gates, and human reviewers cannot distinguish
_why_ something is critical from what it affects.

ADR-020 gave `ActionReasoning` structured tool-call intent; the finding contract
needs an equivalent structured justification. Every finding-emitting role (hunt,
dynamic_validate, prove, tracer) must produce comparable severity rationale so a
CRITICAL from a Qwen hunter means the same thing as a CRITICAL from a DeepSeek
hunter, and the report can render severity sections directly from contract fields.

## What Changes

- **`SeverityRationale` schema** (new, `src/quarry/schemas.py`): a Pydantic model
  with `impact` (what the attacker gains), `exploitability` (how hard it is to
  exploit), and `reachability` (whether an attacker can reach the vulnerable
  code). Each slot carries free-text rationale and an optional list of evidence
  pointers (to `evidence_path` element indices or `source_ref` indices).

- **`CandidateFinding.severity_rationale`**: added as a required (non-optional)
  field — schema-enforced, not prompt-enforced. Backfill: findings parsed from
  older hunts (before the field existed) SHALL default to a rationale tagged
  `legacy` to distinguish pre-contract findings from contract-compliant ones.
  The `legacy` marker is carried on the rationale itself and is never falsified.

- **Schema enforcement for all finding-emitting roles**: `_parse_finding`
  (hunt.py:93) SHALL construct a `SeverityRationale` from the model's output
  fields rather than silently dropping them. When a model output lacks rationale
  fields, the parser SHALL populate a rationale with flag `model_omitted=true`.

- **Report rendering**: the markdown report template SHALL render structured
  severity sections (Impact / Exploitability / Reachability) for each final
  finding, with evidence pointers rendered as links to source references.

- **`FinalFinding` carries `severity_rationale`**: the `FinalFinding` construction sites
  (`quarry_workflows/promotion_stage.py:114` and `quarry_workflows/diff_scan.py:380`)
  SHALL propagate the `severity_rationale` from `CandidateFinding` to `FinalFinding` so
  the contract survives the candidate→final transition. (`promote_to_final_finding_metadata`,
  validation.py:138, only extracts metadata and never builds a `FinalFinding`.)

- **No new calibration mechanics**: the `severity-calibration` spec already
  defines a rule catalogue and post-hoc calibration step. This change adds the
  _structure_ that calibration populates; it does not duplicate calibration logic.

## Impact

- **Specs**: new capability `finding-contract` (ADDED, this delta) — the normative
  home of the severity-rationale contract on findings. This delta does not modify
  `domain-model` or `reporting-and-replay`; their existing requirements (calibrated
  severity fields, report contents) remain satisfied unchanged.

- **Code**: `src/quarry/schemas.py` (new `SeverityRationale`, new fields),
  `src/quarry_activities/hunt.py` (`_parse_finding` rationale construction),
  `src/quarry_activities/validation.py` (promotion carries rationale),
  `src/quarry_activities/reporting.py` (template renders rationale sections),
  `tests/unit/test_finding_contract.py` (new), `tests/unit/test_schemas.py`
  (rationale validation), `tests/golden/report_*.md` (updated).
  No changes to prompt templates — the model output schema in each prompt adds
  `severity_rationale` fields, but that is a prompt-registry update tracked
  separately.

- **Behavior contract**: after this change, every `CandidateFinding` SHALL
  carry a non-null `severity_rationale`. Findings from legacy scans (pre-contract)
  carry a `legacy=true` marker. The report's severity sections are structural —
  legacy findings render the pre-contract disclosure and `model_omitted` findings
  render the omitted-rationale disclosure rather than fabricating text.

- **Non-goals**: changing how calibration works (that's `severity-calibration`),
  changing the `Severity` enum values, changing `Confidence` or `CredibilityLevel`,
  adding CVSS vector strings (explicitly out of scope — CVSS is a rendering
  concern for SARIF export), adding per-role prompt templates (prompt-registry
  concern).

- **Risk**: medium — `severity_rationale` is a new required field on
  `CandidateFinding`. Existing DB records and golden fixtures predate this field.
  Mitigation: the `legacy` backfill path (Pydantic `model_validator` defaulting
  `severity_rationale` to a legacy marker when absent) ensures no existing data
  is rejected on load. Golden fixtures are updated as part of the implementation
  tasks.