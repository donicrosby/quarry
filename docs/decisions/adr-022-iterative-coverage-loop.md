# ADR 022: Iterative Coverage Loop (gapfill + reachability-feedback edges)

## Status

Accepted (amends ADR-009)

## Context

ADR-009 defined the 8-stage pipeline (recon, hunt, validate, gapfill, dedup, prove,
trace, report) and the Temporal `RunScanWorkflow` runs it as a single linear pass.

The reference vision — Cloudflare Project Glasswing — does not run linearly. It runs the
pipeline as an iterative loop with two edges that feed work back into the hunters:

- **Gapfill:** "Hunters flag areas they touched but didn't cover thoroughly. Those areas
  get re-queued for another pass" — to counteract "the model's tendency to drift toward
  attack classes it has already had success with."
- **Feedback:** "Reachable traces become new hunt tasks in the consumer repositories where
  the bug is actually exposed. Closes the loop. The pipeline gets better as it runs."

(Source: Cloudflare *Cyber Frontier Models* / Project Glasswing, blog.cloudflare.com.)

A single linear pass misses vulnerabilities for two distinct reasons, and Glasswing
addresses each with a different edge: models under-cover attack classes they have already
had success with (→ gapfill re-queue), and a *confirmed-reachable* sink implies new hunt
targets in the code paths and consumers that reach it (→ reachability feedback).

Quarry today implements gapfill as a single re-hunt round after validate; there is no
trace→hunt edge, and the pipeline does not iterate to convergence.

### Naming note (important)

The word "feedback" already names a *different* mechanism in this repo. `docs/feedback-loop.md`
describes a **cross-run** loop: human triage labels (TP/FP) feed back into **recon** task
*prioritization* over successive scans (MDASH framing, week 17). The edge introduced here is
**intra-scan**, reachability-driven, and feeds **hunt**, not recon. To avoid overloading the
term, this ADR calls it the **reachability-feedback edge**, and the two are kept distinct.

## Decision

The pipeline is **iterative within a single scan**. Two edges re-queue `hunt` work, both
emitting `AgentTask`s that re-enter the hunt stage (the data model already supports this:
`AgentTask.source ∈ {recon, gapfill, feedback}` and `AgentTask.gapfill_pass`):

1. **Gapfill edge (coverage-driven), after validate.** Gapfill re-queues under-covered
   `(scope, vuln_class)` cells as tasks with `source="gapfill"`, incrementing `gapfill_pass`.
   Runs *before* the expensive prove/trace stages so coverage gaps are closed cheaply.
2. **Reachability-feedback edge (trace-driven), after trace.** Findings confirmed reachable
   by the tracer emit tasks with `source="feedback"` that target the call paths / consumer
   code that reach the confirmed sink.

Both edges return to `hunt`; a round is `hunt → validate → (prove) → trace`, then the two
edges decide whether to iterate. `dedup` runs each round to keep the candidate set clean;
`report` is terminal and runs once after convergence.

### Stop criteria (explicit — Glasswing leaves these implicit)

The loop terminates at the first of:

- **Convergence:** a full round produces **zero** new hunt tasks (coverage floor satisfied
  *and* no new reachability-feedback tasks), or
- **Round cap:** a configured `max_coverage_rounds` (default 3) is reached, or
- **Budget:** the scan budget (`budget_cap_usd`) is exhausted.

Every round must make progress (emit at least one *new* task) or the loop halts — this is
what guarantees termination.

### Invariants

- **Coverage floor** (≥ 2 tasks per focused `vuln_class`) remains a per-scan invariant,
  enforced in code, independent of the loop.
- **Idempotency:** re-hunt tasks are deduped against the set of already-hunted
  `(scope, vuln_class, source)` cells so the same cell is never re-queued indefinitely;
  `gapfill_pass` and the round counter bound re-queues.
- **Prove cost is naturally bounded:** prove only runs on findings *newly promoted to*
  `needs_proof` in that round's validate, so a quiet round does no sandbox work.

## Consequences

### Easier / better

- Higher recall: counters attack-class drift (gapfill) and surfaces reachable-but-unhunted
  consumers (reachability feedback) — the two failure modes Glasswing calls out.
- Reuses existing schema hooks; no new task fields required for the minimum version.

### Harder

- Termination must be deterministic and budget-aware; a non-progressing round must halt the
  loop, not spin.
- The `stage_executions` / resume model must tolerate repeated `HUNT/VALIDATE/PROVE/TRACE`
  executions within one scan (round-scoped idempotency keys, not stage-scoped).
- The TUI pipeline view must show round count, not just a single linear sweep.

### Explicitly not doing

- Modeling reachability-feedback as a 9th conceptual stage. The 8 conceptual stages of
  ADR-009 are unchanged; the loop-backs are **edges** plus a post-trace feedback step. This
  avoids renumbering and the "feedback" name collision.
- Collapsing to a single loop-back point after trace (dropping the early gapfill edge).
  Gapfill-after-validate closes coverage gaps *before* prove/trace run, saving sandbox cost;
  keeping both edges matches Glasswing.

## Alternatives considered

### Keep the single linear pass (ADR-009 as-is)

Rejected. Glasswing reports a single pass under-covers (model drift) and misses reachable
consumers; the loop is the reference design's core recall mechanism.

### One loop-back edge after trace only

Viable and simpler, but it removes the cheap early coverage re-queue. Gapfill before prove
means fewer sandbox executions on duplicate/under-covered cells. Rejected in favor of
Glasswing's two-edge structure.

### Reuse the cross-run triage feedback loop for this

Rejected — different time scale and different target. Triage feedback (feedback-loop.md) is
cross-run and feeds recon priority from human TP/FP labels; the reachability-feedback edge is
intra-scan and feeds hunt from tracer output. They are complementary, not the same loop.
