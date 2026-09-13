## Context

See `proposal.md` — Why. Quarry's static path today is: recon → hunt (one agent
per class, inline `recon_notes` context) → adversarial validation (neutral claim
+ single binary `refute`) → optional live dynamic validation / exploitation loop
→ report. Findings carry an unordered `source_refs` list and a free-choice
`severity`/`confidence` enum. Prompts are versioned Jinja templates in `prompts/`
rendered through the envelope parts (system/developer/evidence/output_schema);
new activities must register in server + worker + tests and stay sandbox-safe
(no `datetime.now`/`uuid4` in workflow code) per the sandboxed-runner rules.

The patterns being adopted come from Keygraph Shannon 3.0's static engine, which
derives from the Apache-2.0 Mantis security-review skills. Shannon runs them as a
ten-stage linear ladder with no execution sandbox, so its terminal verdict is
static confirmation. Quarry is different in two ways that shape this design: it
already has a cross-model ensemble panel doing adversarial work through stage
separation, and it already has a live exploitation loop for real-exploit
confirmation. So we borrow prompt *content and verdict discipline*, not the ladder
topology.

## Goals / Non-Goals

**Goals:**
- Make severity consistent and auditable via a rule-catalogue calibration step.
- Raise validation precision with an itemized, schema-enforced FP checklist.
- Build architecture context once (the KB) and feed it by reference.
- Bias every verdict stage toward never silently dropping a finding.
- Give findings a sink-first ordered evidence path for mechanical dedup.
- Make coverage a proactive guarantee and inject exploratory investigations.

**Non-Goals:**
- Not linearizing Quarry into Shannon's ten-stage ladder; the ensemble panel
  stays the adversarial mechanism.
- Not replacing live exploitation with static confirmation — `PROVISIONALLY_VALID`
  findings still flow to the exploitation loop, which remains the strongest
  confirmation.
- Not changing panel composition, tiers, rate limiting, or provider routing.
- No new runtime service; calibration and KB are stages/activities on existing
  queues.

## Decisions

### D1: Calibration is a separate post-validation stage, not a hunter instruction
A dedicated `calibrate` stage takes the validated finding's raw severity and
emits a calibrated severity/priority plus firing-rule ids, preserving the raw
value. *Why over folding rules into the hunt/validate prompt:* the rule catalogue
is long and mechanical; a hunter optimizing for recall calibrates poorly, and a
separate stage lets the panel vote on *findings* while calibration stays
deterministic-ish and auditable. Rules live in a versioned prompt partial
(`prompts/calibrate/…`, carrying Mantis/Shannon attribution) plus a small
code-side enforcement of hard caps that must not depend on model compliance
(e.g. "not-reproduced ⇒ never CRITICAL"). *Alternative rejected:* pure-code
CVSS calculator — too rigid for the marginal-capability reasoning, which needs
the model to judge prerequisite position.

### D2: Validation checklist recorded as a structured verdict with enforced invariants
Extend the existing validator (which already gets only the neutral claim) so the
verdict is a checklist object — one outcome per constraint — rather than a single
boolean. Invariants ("a failed constraint requires a rejecting verdict"; "a
non-rejecting verdict has no failed entries") are enforced in code at the
recording boundary, and a violating verdict is refused so the model must re-emit.
*Why:* turns "does it feel like a FP?" into itemized, inspectable reasons, and
the enforced invariant is what actually prevents a model marking something valid
while flagging a fatal flaw. *Alternative rejected:* keep the binary refuter and
just lengthen the prompt — no structural guarantee, and the panel would amplify
inconsistent rationales.

### D3: KB is a scan-scoped artifact set produced by a recon activity
A recon activity writes KB records (component entities, vuln-class notes,
dependency graph, index) to the artifact store; the harness writes files, the
agent returns structured output (it has read/find/grep only, no write). Hunt,
gapfill, and validate accept KB references and the context injector resolves
referenced records into the rendered prompt. *Why over inline recon_notes:* built
once, cited many times; decouples context-gathering from analysis; the dependency
graph enables dependency-aware fan-out later. *Alternative rejected:* a live
queryable KB service — unnecessary infra for a per-scan, write-once artifact set;
conflicts with the Redis+S3 no-PVC artifact-store direction only if made stateful,
so it stays plain artifacts.

### D4: Sink-first ordered path replaces reliance on unordered source_refs
Add an ordered evidence-path field to the finding schema with the sink at index
0. Keep `source_refs` during migration for back-compat, deriving the ordered path
where possible; fingerprinting/dedup switches to keying on the sink locator +
title. *Why:* dedup and cross-model correlation become mechanical ("same sink
line + similar title"), matching finding-fingerprinting-and-dedup's needs.

### D5: Coverage guarantee is ledger-side; exploratory injection is planner-side
The coverage ledger enumerates production files and marks each covered /
intentionally-excluded / gap, so gaps are computed, not model-reported. The
gapfill planner injects a bounded configurable fraction (default in the 25–50%
band, single knob) of unconstrained exploratory investigations. *Why split:* the
guarantee is a deterministic accounting property (belongs in code), while the
exploratory hedge is a planning heuristic (belongs in the planner prompt +
config).

### D6: Attribution travels with content
Every lifted prompt partial keeps a header naming Mantis (Apache-2.0) via Shannon,
and `THIRD_PARTY_NOTICES`/`openspec/config.yaml` attribution list is updated.
*Why:* config.yaml requires preserving reference-design attributions; the change
identifier is purpose-named but provenance lives in the content.

## Risks / Trade-offs

- **Added latency and token cost from KB + calibrate stages** → KB is built once
  and replaces repeated inline recon context, partially self-funding; calibration
  runs only on validated candidates (small N). Gate both behind existing budget
  enforcement.
- **Calibration could suppress a real critical (over-capping)** → keep raw
  severity on the finding and record firing rules, so over-caps are visible and
  reviewable; hard caps are limited to well-justified rules (not-reproduced,
  self-contained blast radius).
- **Checklist adds schema surface the model can violate** → boundary enforcement
  refuses invalid verdicts and returns an actionable error for retry, matching the
  existing schema-repair feedback pattern.
- **KB assertions become downstream ground truth; a wrong one blinds later
  stages** → require every KB assertion to cite read source and add a
  spot-check/validate step in the recon activity.
- **Exploratory-investigation injection spends budget on low-signal digs** →
  fraction is a single config knob, bounded, and counts against the same gapfill
  budget ceiling.
- **Sink-first migration could break existing dedup/fingerprints** → keep
  `source_refs` populated through the transition and cut fingerprinting over once
  the ordered path is populated end to end.

## Migration Plan

1. Schema first (TDD): add ordered evidence path + calibrated-severity fields +
   fail-safe verdict defaults; keep `source_refs`. Red → Green.
2. KB recon activity + artifact persistence; context injector resolves references.
   Register activity in server + worker + tests.
3. Calibrate stage + rule-catalogue prompt + code-side hard caps; wire after
   validation.
4. Validator checklist verdict + boundary invariant enforcement.
5. Coverage-guarantee ledger accounting + gapfill exploratory injection knob.
6. Switch fingerprinting/dedup to the sink locator; retire reliance on unordered
   `source_refs` once populated everywhere.

Rollback: each stage is additive and independently revertible. With KB references
absent, hunt/validate fall back to inline context; with calibration disabled,
findings report raw severity; with the checklist flag off, the validator behaves
as the current binary refuter.

## Open Questions

- Exact default value of the exploratory-injection fraction within the 25–50%
  band (tunable later without changing specs or tasks).
- Whether the calibration rule catalogue ships complete on first pass or lands as
  a documented subset with the remainder queued (does not change the stage's
  contract).
