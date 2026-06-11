# ADR 021: Validator independence boundary

## Status

Accepted

## Context

Week 13 introduces an agentic `ValidateActivity` that receives each `CandidateFinding`
produced by the hunt stage and independently assesses whether the finding is real. The
value of this review depends entirely on it being *adversarial*: the validator must reach
its own verdict based on evidence in the code, not by following the hunter's reasoning.

If the validator can see the hunter's reasoning chain, tool trace, model name, or provider,
three failure modes become possible:

1. **Reasoning anchoring.** The validator reads "the hunter said this looks like a command
   injection via the `cmd` parameter" and confirms it without independently verifying the
   data flow. The review becomes a rubber stamp.
2. **Vendor collusion.** If the validator uses the same model or provider as the hunter, a
   systematic bias in that provider's assessment of a pattern propagates unchecked. The
   cross-vendor disagreement signal becomes meaningless.
3. **Trace leakage.** The hunter's tool trace reveals which paths it already checked. A
   validator that sees this will skip those paths, defeating the point of independent review.

The existing `CandidateFinding` carries several provenance fields that must never reach the
validator: `reasoning` (hunter's textual chain-of-thought), `hunter_provider` (the model
vendor), and indirectly any agent step log.

## Decision

### What the validator may receive

The `ValidatorClaim` type contains exactly these fields from `CandidateFinding`:

| Field | Source | Rationale |
|---|---|---|
| `file` | parsed from `affected_component` | Needed to locate the evidence |
| `line_start` | parsed from `affected_component` | Needed for `read_file` / `grep` targeting |
| `line_end` | parsed from `affected_component` | As above |
| `vuln_class` | `CandidateFinding.vuln_class` | Needed to choose the right validation heuristics |
| `description` | `CandidateFinding.hypothesis` | The claim to validate |
| `affected_code_snippet` | optional snippet attached to the finding | Concise context |

`ValidatorClaim` is a separate type (not a sub-model or view of `CandidateFinding`).
`validate_claim_from_finding(finding) -> ValidatorClaim` is the **only** permitted
construction path. The full `CandidateFinding` must never be serialised into a prompt or
passed to `run_agent_loop` with role `"validate"`.

### What the validator must never receive

- `CandidateFinding.reasoning` — the hunter's chain-of-thought
- `CandidateFinding.hunter_provider` — the model vendor used for hunting
- Any field derived from `AgentStep` records (tool_calls, model_invocation_id)
- Model name or provider of the hunt agent

Enforcement: a test in `tests/unit/test_validator_claim.py` asserts that neither the
serialised `ValidatorClaim` payload nor any field of the claim model contains hunter
reasoning text or the `hunter_provider` value.

### cross_vendor_disagreement computation

`ValidationResult.cross_vendor_disagreement` is set to `True` when the provider of the
hunt role on the active panel differs from the provider of the validate role:

```python
hunt_provider = panel["hunt"].provider
validate_provider = panel["validate"].provider
cross_vendor_disagreement = hunt_provider != validate_provider
```

Comparison is **string equality of provider names** (e.g. `"anthropic"` vs `"openai"`), not
model names. Two different Anthropic models on both sides → `False`; Anthropic hunt with
OpenAI validate → `True`.

`DEFAULT_PANEL` assigns `provider="mock"` to both roles in development. Cross-vendor
disagreement is only meaningful in a real scan where `hunt` and `validate` are configured
to different providers (e.g. via `quarry.toml`).

### Why the coverage floor is enforced in code

`enforce_coverage_floor` in `src/quarry_models/coverage.py` appends synthetic gapfill
`AgentTask`s for any focused vuln_class that falls below `min_per_class` (default 2).

This is a correctness invariant, not a hint:

- Prompts can be ignored or misunderstood. A model that finds nothing in a class can return
  an empty list without violating any instruction.
- The floor must fire even when the model returns empty output — this is tested explicitly
  in `tests/unit/test_coverage_floor.py::test_does_not_add_when_already_at_floor`.
- Operator focus (the `vuln_classes` focus list) narrows the floor's scope by design.
  Feedback may not reduce coverage below `min_per_class` within the focused set.

## Consequences

### Positive

- Independent agentic validation produces meaningful signal: confirmations and rejections
  reflect a second model's genuine assessment, not anchored reasoning.
- The `cross_vendor_disagreement` flag provides an operator-visible signal when two
  providers disagree, which is a strong indicator of a genuine ambiguous case.
- The coverage floor guarantees scan completeness: operator-configured classes always have
  at least `min_per_class` hunt attempts per scan, regardless of model output.

### Negative / trade-offs

- The validator cannot use the hunter's tool trace to avoid redundant reads. In practice
  this is a minor cost: the validator uses `read_file` and `grep` which are fast, and the
  benefit of independent re-examination outweighs the redundancy.
- Building `ValidatorClaim` requires parsing `affected_component` string notation. If the
  notation is extended, `_parse_file_and_lines` in `validation.py` must be updated.

## Related ADRs

- ADR-014 (agentic harness) — the agent loop and role system this boundary applies to
- ADR-017 (live-dynamic validation) — `dynamic_validate` role for live HTTP corroboration,
  which separately enforces the same validator-independence boundary
- ADR-019 (prompt registry) — no hunter-provenance text may appear in any prompt template
- ADR-020 (action reasoning) — `ActionReasoning` from hunt steps is also excluded from
  `ValidatorClaim`; test in `tests/unit/test_validator_independence_reasoning.py`
