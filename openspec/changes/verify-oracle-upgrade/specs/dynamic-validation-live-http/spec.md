## ADDED Requirements

### Requirement: Statistical timing path for delay-annotated SQLi probes
The `sql_injection_evaluator` SHALL apply a statistical timing analysis when the probe's `HttpRequestSpec` carries an `injected_delay_ms` value. The timing path SHALL sample N baseline and M attack request latencies, compute robust noise-floor sigma via max(classical standard deviation, MAD × 1.4826), and SHALL return corroborated only after BOTH the initial statistical pass AND delay-ladder confirmation succeed.

#### Scenario: Statistical pass proceeds to ladder confirmation
- **WHEN** (i) induced delay ≥ max(3σ, 0.6 × injected_delay_ms) AND (ii) at least ⌈M/2⌉ attack samples are at or above baseline-median + injected_delay_ms/2
- **THEN** the timing path records a statistical pass and proceeds to ladder re-probe; corroborated is returned only after the ladder confirms

#### Scenario: Induced delay falls below noise floor
- **WHEN** the induced delay is below 3σ (classical or robust, whichever is larger)
- **THEN** the timing path returns not-corroborated (no statistically distinguishable delay effect)

#### Scenario: Neither statistical pass nor pure noise-floor — inconclusive
- **WHEN** induced delay ≥ 3σ but fails the majority-consistency gate, or passes the majority gate but fails the max(3σ, 0.6×delay) combined threshold
- **THEN** the timing path returns inconclusive with reason recorded in the receipt

#### Scenario: Absent injected_delay_ms falls through to differential path
- **WHEN** the probe's `HttpRequestSpec` does NOT carry `injected_delay_ms`
- **THEN** the evaluator applies the hardened differential path (normalization → indicator → Jaccard → exact comparison) without consulting latency

### Requirement: Delay-ladder confirmation defeats coincidental-endpoint false-positives
When a timing-oracle candidate clears the initial statistical pass, the workflow SHALL dispatch a second batch of M attack probes at 2× injected delay, subject to the R7 budget gate. The ladder batch SHALL reuse the initial baseline. The evaluator SHALL require ladder_induced ∈ [1.4, 2.6] × first_induced AND ladder_induced ≥ first_induced + 0.6 × injected_delay_ms; failing either SHALL return inconclusive (ambiguous, not proof).

#### Scenario: Ladder step scales proportionally
- **WHEN** the ladder batch induced delay falls within [1.4, 2.6] × first_induced AND is at least first_induced + 0.6 × injected_delay_ms
- **THEN** the timing path returns corroborated with ladder_scale_factor in the receipt

#### Scenario: Ladder step fails to scale
- **WHEN** the ladder batch induced delay falls outside [1.4, 2.6] × first_induced OR fails the additive floor
- **THEN** the timing path returns inconclusive with reason `ladder_failed_to_scale` (a single-delay signal that does not scale is ambiguous, not proof; the lead stays open for further proof)

### Requirement: Timing path returns three-way verdict with audit receipt
The timing path SHALL surface a receipt on the `finding.dynamic_validated` event payload. The evaluator SHALL return the receipt as a `VerdictReceipt` via `evaluate_live_verdict_with_receipt(cls, ev) -> tuple[Verdict, VerdictReceipt | None]` (mirroring `evaluate_live_verdict_with_source`); the workflow SHALL serialize it into the event payload.

#### Scenario: Corroborated finding carries full timing receipt
- **WHEN** the timing path returns corroborated
- **THEN** the `finding.dynamic_validated` event payload includes a `timing_receipt` carrying N, M, baseline_median, attack_median, mad, robust_sigma, classical_sigma, threshold, induced_delay_ms, majority_count, majority_required, and ladder_scale_factor

#### Scenario: Inconclusive or not-corroborated finding carries partial receipt with reason
- **WHEN** the timing path returns inconclusive or not-corroborated
- **THEN** the `finding.dynamic_validated` event still carries `timing_receipt` with all computed statistics and a `reason` string

### Requirement: Payload-echo normalization in differential body comparison
Differential evaluators SHALL normalize both the attack and baseline response bodies by replacing every occurrence of the probe's injected payload strings with the `§INJECTED§` placeholder token before comparing bodies for divergence, so a reflected payload does not masquerade as a semantic difference. The injected-values list SHALL be declared by the proposing agent on `HttpRequestSpec.injected_values` alongside the payload, then transported via `LiveProbeEvidence.injected_values`.

#### Scenario: Reflected payload without normalization
- **WHEN** the attack body contains an injected value and the baseline body contains a distinct injected value with otherwise identical structure
- **THEN** payload-echo normalization replaces each injected value with `§INJECTED§` in both bodies, so they emerge structurally equivalent and the evaluator returns not-corroborated

#### Scenario: Full body with echo-only difference
- **WHEN** after normalization the attack and baseline bodies are byte-identical
- **THEN** the differential evaluator returns not-corroborated regardless of raw-body divergence

### Requirement: Token-Jaccard similarity as disproven threshold
Differential evaluators SHALL compute token-Jaccard similarity between normalized attack and baseline bodies. Similarity ≥ 0.95 with matching HTTP status code SHALL return not-corroborated. Similarity ≥ 0.95 with differing status code SHALL return inconclusive. Similarity below 0.95 SHALL fall through to exact-body-comparison.

#### Scenario: High-similarity bodies with matching status are declared equivalent
- **WHEN** normalized attack and baseline bodies have token-Jaccard similarity ≥ 0.95 and identical HTTP status codes
- **THEN** the evaluator returns not-corroborated (structurally equivalent — the injection produced no observable effect)

#### Scenario: High-similarity bodies with mismatched status return inconclusive
- **WHEN** normalized bodies have similarity ≥ 0.95 but HTTP status codes differ
- **THEN** the evaluator returns inconclusive (bodies are equivalent but the server treated them differently)

#### Scenario: Divergent bodies fall through to exact comparison
- **WHEN** normalized bodies have similarity below 0.95
- **THEN** the evaluator falls through to exact-body-comparison; with a 2xx primary, divergence returns corroborated and identical returns not-corroborated; a non-2xx primary returns inconclusive regardless of divergence

### Requirement: Hunter-supplied success indicator outranks generic heuristics
When the probe specification carries an optional `indicator` string, differential evaluators SHALL test for that indicator in the raw (pre-normalization) attack and baseline response bodies before applying normalization or similarity heuristics. Present-in-attack-only SHALL return corroborated. Absent-from-both SHALL return not-corroborated. Present-in-both SHALL return None (fall through to generic heuristics).

#### Scenario: Indicator present in attack body only
- **WHEN** the probe spec carries an `indicator` string and that string appears in the raw attack response body but is absent from the raw baseline response body
- **THEN** the evaluator returns corroborated without consulting normalization, status-code, or similarity heuristics

#### Scenario: Indicator absent from both bodies
- **WHEN** the probe spec carries an `indicator` string and that string is absent from both raw attack and baseline response bodies
- **THEN** the evaluator returns not-corroborated and does NOT fall through to generic heuristics

#### Scenario: Indicator present in both bodies — fall through to generic heuristics
- **WHEN** the probe spec carries an `indicator` string and that string appears in BOTH raw attack and baseline response bodies
- **THEN** the evaluator returns None (cannot decide from indicator alone) and proceeds to payload-echo normalization and generic heuristics

#### Scenario: No indicator supplied — generic heuristics apply
- **WHEN** the probe spec does NOT carry an `indicator` string
- **THEN** the evaluator falls through to normalized-body comparison via token-Jaccard similarity and status-code heuristics

### Requirement: Timing-probe dispatch counts against a per-scan probe budget
The dynamic-validation workflow SHALL maintain a timing-probe sub-budget (`timing_probes_remaining`, initialized from a configurable limit defaulting to 20) as loop-local state. Each HTTP request dispatched for timing purposes (baseline, attack, or ladder) SHALL decrement this counter. The ladder re-probe batch SHALL only dispatch when `timing_probes_remaining` is sufficient for the full batch size (M probes).

#### Scenario: Ladder re-probe skipped when initial batch disproves
- **WHEN** the initial timing batch (N baseline + M attack) returns not-corroborated or inconclusive
- **THEN** no ladder re-probe is dispatched and `timing_probes_remaining` reflects only the initial batch

#### Scenario: Ladder re-probe dispatched when initial batch clears threshold and budget remains
- **WHEN** the initial timing batch returns a statistical pass and `timing_probes_remaining` ≥ M
- **THEN** a second batch at 2× injected delay is dispatched and `timing_probes_remaining` decrements for each ladder request

#### Scenario: Statistical pass with insufficient budget returns inconclusive
- **WHEN** the initial timing batch returns a statistical pass but `timing_probes_remaining` < M
- **THEN** no ladder re-probe is dispatched and the workflow records `LIVE_INCONCLUSIVE` with reason `budget_exhausted` (corroborated requires ladder confirmation)

### Requirement: Timing oracle respects egress policy and scope containment
Timing-oracle probe targets SHALL pass through the same guarded network path as existing dynamic-validation probes; targets not in `allowed_hosts` SHALL be refused before egress; the timing class SHALL be gated by the same multi-layer opt-in as all live-validation capability per the `dynamic-validation-live-http` spec.

#### Scenario: Out-of-scope timing probe refused
- **WHEN** a timing-oracle probe would target a host or path outside the authorized scope
- **THEN** the guarded network path refuses the request before any egress occurs

#### Scenario: Timing oracle disabled when live validation is not authorized
- **WHEN** live validation is not opted in
- **THEN** timing-oracle probes are never dispatched regardless of evaluator registration