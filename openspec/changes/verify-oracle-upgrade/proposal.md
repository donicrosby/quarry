# Proposal: verify-oracle-upgrade

## Why

The current verdict-evaluator registry (`src/quarry_activities/verdict_evaluators.py`)
has three per-class evaluators — SSTI (single marker), SQLi (boolean-differential),
and SSRF (differential) — all operating on exact body comparison and HTTP status codes.
This leaves two verified oracle patterns from Pentest-Swarm's security-testing research
on the table:

1. **Blind-SQLi / timing-based injection classes have no statistical evaluator.**
   The existing SQLi evaluator assumes a boolean-differential body divergence, which
   fails for blind SQLi where the only observable is latency. Race-condition classes
   (planned, not yet a VulnerabilityClass) share the same timing-only profile.

2. **Differential evaluators are vulnerable to payload-echo false-positives.**
   When the target reflects the injected payload (id=`1' OR '1'='1` vs id=`999999`),
   the bodies diverge by construction and the evaluator spuriously returns corroborated.
   The exact-equality check also fails on irrelevant divergence (CSRF tokens, timestamps,
   nonces) that token-set comparison catches.

Pentest-Swarm AI ships two countermeasures verified in its oracle subsystem
(`internal/swarm/verify/oracle/timing.go:106-182`, `differential.go:98-196`):

- **Statistical timing oracle** with MAD-robust noise floor, majority-consistency
  rule, and delay-ladder linearity confirmation that kills coincidental-slow-endpoint
  false-positives.
- **Differential hardening** — payload-echo normalization, token-Jaccard similarity
  (≥0.95 + same status = Disproven), and a hunter-supplied success `indicator` string
  that outranks all generic heuristics.

Both are deterministic, non-LLM mechanisms (re-derivable pure statistics and set
operations) that slot directly into Quarry's existing `VerdictEvaluator` registry
without changing the registry protocol.

## What Changes

1. **`sql_injection_evaluator` extended with a composition dispatch** — the existing
   SQLi evaluator gains an internal timing path activated when the probe's
   `HttpRequestSpec` carries `injected_delay_ms`. Delay-annotated probes route to
   the statistical timing path (R1/R2); probes without a delay annotation route to
   the hardened differential path (R4–R6). This preserves backward compatibility
   (boolean SQLi probes without delay still use the differential path) and avoids
   a registry self-contradiction under the one-evaluator-per-class protocol.
   The evaluator consumes N=5 baseline + M=3 attack probe latencies, applies
   max(classical σ, MAD × 1.4826) noise-floor conservatism, enforces majority-sample
   consistency, and requires delay-ladder confirmation at 2× injected delay
   within [1.4, 2.6] band plus additive floor before returning corroborated. Returns
   the same three-way verdict (corroborated/not-corroborated/inconclusive) with
   a `timing_receipt` dict surfaced on the `finding.dynamic_validated` event.

2. **Differential evaluator hardening** applied to the SQLi non-delay path and to
   `ssrf_evaluator` (and inherited by all future differential evaluators):
   payload-echo normalization replaces injected values with `§INJECTED§` placeholders
   in both bodies before comparison; token-Jaccard similarity ≥0.95 with matching
   status returns not-corroborated (≥0.95 with differing status returns inconclusive);
   and an optional `indicator` string on the probe spec outranks generic heuristics
   when present (checked on raw pre-normalization bodies). The exact-body-comparison
   path remains as the divergence-detection fallback below the similarity threshold.

3. **Schema extensions** — `HttpRequestSpec` gains `injected_delay_ms: int | None`
   and `injected_values: tuple[str, ...] | None` (both declared by the proposing
   agent alongside the payload) plus `indicator: str | None`. `LiveProbeEvidence`
   gains `elapsed_ms: int | None`, `injected_values: tuple[str, ...] | None`, and
   `indicator: str | None` — each transported from the probe spec's `HttpRequestSpec`
   field at workflow dispatch time, mirroring how `body_text`/`status_code` flow.
   Absent `injected_delay_ms` routes the evaluator to the differential path (R1 S4);
   the timing path never guesses a delay.

4. **Workflow-side timing dispatch** — the dynamic-validation stage in
   `src/quarry_workflows/run_scan.py` extended to dispatch N+M timing probes (and
   optional ladder re-probes) for evaluators carrying a `timing_profile: true` flag
   on the `EvaluatorSpec`, collecting per-probe latencies from
   `HttpResponseCapture.elapsed_ms`. Timing evidence assembled as
   primary=first attack probe, additional = N baseline then M−1 attack probes.

5. **Budget and egress integration** — timing probes count against a loop-local
   `timing_probes_remaining` counter (default 20, configurable); ladder re-probes
   only fire when the initial statistical pass clears AND the counter has headroom;
   all timing traffic passes through the existing guarded network path
   (`allowed_hosts` + scope exclusions).

## Impact

- **Affected specs:** `dynamic-validation-live-http` (ADDED 8 requirements, 22 scenarios).
- **Affected code:** `src/quarry_activities/verdict_evaluators.py` (extended SQLi
  evaluator with timing path + differential hardening helpers; new `VerdictReceipt`
  dataclass; `evaluate_live_verdict_with_receipt` tuple wrapper; `timing_profile`
  flag on `EvaluatorSpec`), `src/quarry_workflows/run_scan.py` (timing dispatch loop
  with probe-budget counter; receipt serialization), `src/quarry/schemas.py`
  (`injected_delay_ms` + `injected_values` + `indicator` on `HttpRequestSpec`;
  `elapsed_ms` + `injected_values` + `indicator` on `LiveProbeEvidence`).
- **Non-goals:** This change does NOT add a `RACE_CONDITION` VulnerabilityClass — the
  timing evaluator is initially scoped to `SQL_INJECTION` (blind-SQLi) and is wired so a
  future race-condition class can register under the same evaluator with a class-specific
  injected-delay profile.
- **Attribution:** Oracle mechanisms derived from Pentest-Swarm AI (AGPL-3.0, per
  `internal/swarm/verify/oracle/timing.go:106-182` and `differential.go:98-196`)
  — re-derived as pure statistics and set operations for Quarry's Python codebase
  with no code import. Attribution recorded in `THIRD_PARTY_NOTICES.md`.

## Design decisions (r2/r3 revision)

- **B1 — Composition over replacement.** One `sql_injection_evaluator` dispatches
  internally on `injected_delay_ms` presence. This keeps the registry one-evaluator-per-class,
  preserves boolean SQLi through the differential path, and adds blind-SQLi through the
  timing path. The evaluator is NOT replaced by a standalone `timing_evaluator`.
- **B2 — `injected_delay_ms` on `HttpRequestSpec`.** Declared by the proposing agent alongside
  the delay payload. Absent → the evaluator routes to the differential path (R1 S4);
  the timing path never guesses a delay.
- **B3 — Evidence fields on `LiveProbeEvidence`.** `elapsed_ms`, `injected_values`, and
  `indicator` are set at workflow dispatch time, mirroring how `body_text`/`status_code` flow.
  No per-probe closure seam needed.
- **B4 — Count-based timing-probe sub-budget.** `timing_probes_remaining` is loop-local
  workflow state, independent from the dollar-cost validation budget. Named explicitly in R7.
- **B5 — `injected_values` provenance on `HttpRequestSpec`.** `injected_values:
  tuple[str, ...] | None` is declared by the proposing agent on `HttpRequestSpec`
  alongside the payload (the same precedent as `injected_delay_ms`), then transported
  to `LiveProbeEvidence.injected_values` at workflow dispatch. No structural derivation
  or regex-guessing at dispatch — the agent that authors the payload names the injected
  substrings, so R4 normalization and R5 Jaccard consume agent-declared values.
- **S6 — Boundary comparators aligned to the source (inclusive ≥).** The timing path
  uses inclusive thresholds matching timing.go:136 (`d >= cut`) and :143
  (`induced >= strong`); `induced == threshold` is a statistical pass, never inconclusive.
- **S7 — Ladder-failure verdict aligned to the source Inconclusive.** A single-delay
  signal that fails to scale is ambiguous, not proof (timing.go:174-179), so a ladder
  failure returns inconclusive (the lead stays open for further proof), not not-corroborated.