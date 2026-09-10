# ADR-026: Harness Engineering Principles

- **Status**: Accepted
- **Date**: 2026-09-10
- **Deciders**: doni

## Context

Analysis of Cloudflare's Project Glasswing writeup, Microsoft's MDASH posts, Keygraph Shannon's repo, and Anthropic's harness engineering posts surfaced a consistent set of principles for agentic vulnerability-discovery harnesses. Quarry's architecture already embodies most of them; this ADR records them as binding design rules so future changes don't erode them, and records the deliberate deviations.

## Decision

Quarry adopts these harness design rules:

1. **Narrow scope over broad scope.** Every agent task is one attack class plus a scope hint with shared recon context (ArchitectureDoc, prior coverage). Never prompt an agent with "find vulnerabilities in this repo" — coverage comes from many narrow parallel tasks with post-hoc dedup, not one exhaustive agent.

2. **Adversarial validation.** Findings are reviewed by an agent that did not produce them, with a different prompt and no ability to emit findings. An agent must never be the sole judge of its own output.

3. **Split the exploit chain across roles.** "Is this code buggy?", "is it reachable?", and "can it be proven?" are separate stages with separate roles. Do not collapse them into one prompt.

4. **Findings are data, not prose.** All finding-emitting roles produce schema-validated structured output. Reports are rendered from structured findings; the model never writes the report directly.

5. **The pipeline is model-agnostic.** Any stage's model is configuration. No stage may hardcode a provider or model family.

6. **Handoff over compaction for long tasks.** When an agent's context budget is exhausted, state transfers to a fresh instance through versioned artifacts (ArchitectureDoc, coverage ledger, hunt handoff), not through conversation summarization alone. Candidate findings must never be silently dropped by a context reset.

7. **The harness is the product.** Prefer harness-side structure (task shaping, tool constraints, artifact contracts, refutation passes) over prompt-side heroics. Re-evaluate the harness when models improve; delete what stops being load-bearing.

8. **Every finding carries provenance.** Model, prompt version, config, and run identity are recorded per finding so any result can be attributed and rerun deterministically.

9. **Never auto-remediate.** Quarry does not generate or apply patches. (Cloudflare observed model-written patches that fixed the target bug while breaking adjacent behavior; remediation is a human-owned workflow, findings feed it as data.)

10. **Proof over speculation.** The pipeline is tuned to over-report internally at hunt time, but externally reported findings must carry proof or an explicit honest-gaps disclosure. Hedged findings ("possibly", "potentially") never reach the final report as findings.

## Non-goals (deliberate deviations)

- **No ten-stage agentic SAST lane** at this time. Whether a static-analysis lane earns its complexity is an open question tracked as a spike on the board (evaluate with measurement before adopting).
- **No auto-patch generation** (rule 9).
- **No 100+ agent panels as a default.** Role specialization exists; model ensemble per role is configuration, not a requirement.

## Consequences

- New pipeline stages must state which rule(s) they serve; PRs that violate a rule need an ADR amendment.
- The adversarial-refutation, handoff-artifact, finding-contract, per-agent-log, trace-feedback, and benchmark-expansion tickets on the quarry board operationalize these rules.
