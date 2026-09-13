## Why

Quarry's static candidate pipeline does enumerate → trace → judge in one hunter
agent per class, then leans on the ensemble panel and a single binary refuter to
suppress false positives. Two weaknesses fall out of that shape: severities are
free-choice enums with no rubric, so they vary model-to-model and the panel
amplifies the noise; and false-positive suppression rests on one "can you refute
this?" pass with no itemized failure modes. We also re-derive architectural
context inline on every hunt/gapfill/validate call instead of building it once.

Recent public work on agentic white-box analysis (Keygraph's Shannon 3.0, whose
static engine derives from the Apache-2.0 Mantis security-review skills)
demonstrates prompting patterns that directly target these weaknesses. This
change adopts the patterns that fit Quarry's architecture, expressed in Quarry's
own terms — it does **not** linearize Quarry into Shannon's ten-stage ladder, and
it keeps the ensemble panel and live exploitation loop, which already supply the
adversarial pressure and real-exploit confirmation that Shannon's static-only
engine lacks.

## What Changes

- **Marginal-capability severity calibration.** Add a calibration step whose
  final severity is bounded by the *new* capability an exploit grants over the
  attacker's prerequisite position, using a mechanical catalogue of
  force-downgrade / force-cap rules (e.g. self-contained blast radius caps at
  MEDIUM; unreproduced/static-only caps below CRITICAL; probabilistic-LLM and
  XSS vectors default low and cap at HIGH). Severity stops being a free enum.
- **Adversarial review as a negative-constraint checklist.** Expand the refuter
  into a validator that assumes every finding is a false positive by default,
  judges from code only while explicitly ignoring the finder's prose reasoning,
  and walks an itemized list of false-positive patterns (hypothetical misuse,
  defense-in-depth-only, pedantic linting, mitigation-stretching, source-coherence
  / anti-hallucination, trust-boundary tracing). The verdict is recorded as a
  machine-checked checklist whose invariants the schema enforces.
- **Durable Knowledge Base.** Add a reconnaissance artifact set (component
  entities, relevant vulnerability-class notes, an import/dependency graph, a
  root index) built once and read by later stages, so hunt/gapfill/validate
  consume compiled context via references instead of re-deriving it inline.
- **Fail-closed / fail-safe verdict defaults.** Verdict-producing stages bias
  toward never silently dropping a finding: production-vs-sample intent defaults
  to "production" unless every signal says otherwise; a stage that cannot
  re-verify a finding (missing file, out-of-range line) defaults to the
  conservative "keep" verdict rather than discarding it.
- **Sink-first evidence-path convention.** Findings carry an ordered code path
  whose first element is the sink (the flaw's primary location), followed by the
  steps back toward the source, making dedup and downstream correlation
  mechanical.
- **Proactive coverage guarantee + injected exploratory investigations.** The
  hunt/gapfill planner must account for every production file (nothing
  unexamined) and deliberately spend a bounded fraction of investigations on
  unconstrained, no-context "explore this area" sweeps that ignore the current
  threat model, hedging against tunnel vision.

All lifted prompt *content* carries its Mantis (Apache-2.0, via Shannon)
provenance header, consistent with `openspec/config.yaml`'s requirement to
preserve reference-design attributions.

## Capabilities

### New Capabilities
- `severity-calibration`: A post-validation stage that bounds a finding's final
  severity/priority by marginal attacker capability using a fixed rule catalogue,
  producing a calibrated, auditable severity independent of the hunter's raw guess.
- `knowledge-base`: A durable, interlinked reconnaissance artifact set (component
  entities, vulnerability-class notes, dependency graph, index) built once and
  referenced by later stages as shared, compiled context.

### Modified Capabilities
- `adversarial-validation`: Refutation becomes an itemized negative-constraint
  checklist with a default-false-positive stance and schema-enforced verdict
  invariants; validator still receives only the neutral claim.
- `hunt-stage`: Candidate findings adopt the sink-first ordered evidence path,
  and hunters may be assigned unconstrained exploratory investigations.
- `coverage-ledger-and-gapfill`: Coverage becomes a proactive guarantee (every
  production file accounted for) and the gapfill planner injects a bounded
  fraction of unconstrained exploratory investigations.
- `domain-model`: The finding schema gains the ordered sink-first evidence path,
  the calibrated-severity fields, and the fail-safe verdict defaults.

## Impact

- **Prompts** (`prompts/`): new `calibrate/` and `recon`/knowledge-base templates;
  expanded `validate/refute`; `hunt`/`gapfill` output-schema and planner changes.
  Lifted content carries Mantis/Shannon attribution headers.
- **Schemas** (`src/quarry/schemas.py`): ordered sink-first evidence path on
  findings, calibrated-severity fields, verdict-default semantics.
- **Workflow** (`src/quarry_workflows/run_scan.py`, activities): new calibration
  stage and knowledge-base recon artifact; wiring of KB references into
  hunt/gapfill/validate. New activities register in all required places
  (server + worker + tests) per the sandboxed-runner rules.
- **No change** to the ensemble panel, live-recon, or exploitation loop beyond
  consuming calibrated severities and KB context. Entirely additive to the
  existing agentic-only sourcing path.
- Relates to the queued OWASP-hunter / duplicate-aware gapfill enhancements.
