# ADR 020: Mandatory action reasoning and deterministic vagueness rejection

## Status

Accepted

## Context

From week 11, the agent loop (`run_agent_loop`) accepts a typed answer or a `proposed_actions`
list from the model each turn. The proposal type `ProposedAction` is referenced by name in
ADR-014 and week-11 planning but **was never defined with fields**. No field in any schema
records *why* the agent called a tool — only what it called and what came back
(`args_hash`, `stdout_ref`). When a scan misbehaves or produces a surprising finding,
there is no logged thought process to audit.

The gap compounds in week 13 as the `validate`, `gapfill`, and `dedup` roles come online
alongside `hunt` and `recon`. All five roles use the same loop and the same untyped
proposal struct. A `hunt` agent that calls `http_request` with a vague rationale like
"testing the endpoint" and a `validate` agent that calls `read_file` with no stated
hypothesis produce identical audit records — two tool calls with no recoverable intent.

The open question: can vague reasoning be detected without a second model in the loop?
Answer: yes, if reasoning is a **structured object** (not free prose) and the checks are
**deterministic** over the structure. A model that can only say "testing the exploit" and
cannot name a concrete parameter, an expected observable, or a specific file:line is
not saying anything auditable. Requiring a typed `ActionReasoning` with four non-optional
slots forces specificity by construction. Detecting vacuousness in those slots is a
pure function over strings — no model required.

The live-observability gap is related: even if reasoning is persisted to the audit trail,
an operator watching a running scan today sees nothing of the agent's thought process.
`WorkflowEvent` (week 1) is the existing event model; extending it with iteration-grained
events closes the live-streaming gap without new infrastructure.

Constraints:

- **ADR-019 (prompt registry):** week 12.5 is complete. The re-prompt feedback message must
  be rendered from a registry template (`prompts/_feedback/vague_reasoning.j2`), not an
  inline Python string.
- **`CandidateFinding.reasoning` is validator-blind.** `schemas.md:483` marks it
  `# NEVER shown to the validator`. The new `ActionReasoning` is a different concept
  (tool-call intent) and must also never reach the validator — for the same independence
  reason, and because it is model-authored first-party text, not a claim about a finding.
- **`scrub()` before every emit.** The model could echo target content into its reasoning.
  All reasoning text passes through `scrub()` before persistence, logging, `WorkflowEvent`
  payload, and TUI display.
- **No model in the loop for vagueness detection.** Deterministic checks only; an LLM
  judge is explicitly deferred (see §7 and Explicitly not doing).

## Decision

Define `ProposedAction` with a mandatory structured `ActionReasoning` field. Run four
deterministic checks on the reasoning before executing any tool call. On rejection,
re-prompt the same turn with specific feedback (registry template); halt after
`reasoning_max_retries` with a new `reasoning_rejected` stop reason. Persist reasoning
to `ToolInvocation` / `AgentStep` for audit. Emit scrubbed `WorkflowEvent`s each
iteration for live operator observability via the TUI and `--verbose` CLI.

### 1. `ProposedAction` and `ActionReasoning`

```python
class ActionReasoning(BaseModel):
    hypothesis: str        # what the agent believes and is testing RIGHT NOW
    target_ref: str        # concrete locator: "GET /search?q=", "user.py:42", "param `id`"
    expected_evidence: str # the specific observable signal that confirms or denies this
    why_this_tool: str     # why this particular tool + args advances the hypothesis

class ProposedAction(BaseModel):
    kind: str              # checked against ROLE_ALLOWED_ACTION_KINDS[role]
    tool_name: str
    args: dict
    reasoning: ActionReasoning  # MANDATORY — every field must be non-empty
```

`ActionReasoning` is **operator-facing** and **audit-facing** — it is logged, streamed,
and persisted. It is **not** `CandidateFinding.reasoning` (that field describes why a
finding is real and is validator-blind by policy). These are different fields with
opposite visibility properties; do not conflate them.

### 2. Deterministic check suite

`check_vague_reasoning(action, task_context, args) -> ReasoningCheckResult` in `guards.py`,
run on every proposed action before execution. Four sub-checks:

```python
class ReasoningCheckResult(BaseModel):
    passed: bool
    failed_checks: list[str]   # sub-check names that failed
    detail: str                # human-readable feedback message (for re-prompt)
```

**Sub-checks:**

- **presence** — every `ActionReasoning` field is non-empty and above a minimum token count
  (configurable, default 4 tokens). Rejects empty or single-word slots.
- **context_reference** — `hypothesis` or `target_ref` must name the current task's
  `vuln_class` (or a recognized synonym from config) AND include a concrete locator: a URL
  path, parameter name, or `file.py:line` format. Rejects "testing XSS" with no named param.
- **lexicon** — rejects reasoning dominated by banned generic phrases: "test the exploit",
  "check the endpoint", "see what happens", "verify the vulnerability", "investigate",
  "probe it". `expected_evidence` may not be "it works", "confirmed", "vulnerable", or
  semantically equivalent blank claims.
- **args_coherence** — the claimed `target_ref` must be consistent with the actual `args`:
  an `http_request` URL path must contain the route named in `target_ref`; a `read_file`
  path must contain the file named; for `prove`/`dynamic_validate`, the payload arg must
  contain a token appropriate to `vuln_class` (script-like token for XSS, quote or UNION
  for SQLi, path traversal sequence for path traversal).

**Graduated strictness by action kind:**

| Action kind | Checks applied |
|-------------|---------------|
| Read-only recon (`read_file`, `list_dir`, `grep`, `search_code`, `treesitter_query`) | presence + context_reference + lexicon |
| High-risk (`http_request`, `opengrep`, `codeql_query`) | all four |
| Proof/exploit (`dynamic_validate`, prove payloads) | all four + strictest args_coherence |

Checks are **permissive**: reject only clearly-vague reasoning. Borderline cases are caught
by the re-prompt loop (§3). The lexicon and strictness tiers live in config (see §7) and
evolve without code changes.

All checks are pure functions over the action, task context, and args — deterministic and
reproducible. No model call.

### 3. Re-prompt-then-halt loop behavior

When `check_vague_reasoning` rejects an action:

1. Render the feedback message from `prompts/_feedback/vague_reasoning.j2` (registry
   template, ADR-019 — no inline prompt text). Template variables: `failed_checks`,
   `tool_name`, `vuln_class`, per-check hint strings. Example rendered output:
   *"The reasoning for `http_request` failed the `context_reference` check: name the
   exact parameter you are testing (e.g. `?q=`) and the exact response signal you expect
   (e.g. `<script>alert` in the response body)."*
2. Append as a **developer-role message** (instruction envelope, never `<target_content>`).
3. Increment `reasoning_retries` counter (separate from iteration count). Do not execute
   the action. Do not advance the iteration counter used for `max_iterations` enforcement.
4. Retry up to `reasoning_max_retries` (default 2, configurable).
5. On exhaustion, return `AgentLoopResult` with `stop_reason="reasoning_rejected"` and
   record the final rejected reasoning + failing checks in the terminal `AgentStep`.

### 4. Provenance persistence

```python
# ToolInvocation gains two fields:
reasoning_summary: str | None = None    # inlined hypothesis line for fast scan
reasoning_ref: ArtifactRef | None = None  # full ActionReasoning artifact (via ArtifactStore)

# AgentStep gains one field:
rejected_reasoning_refs: list[str] = Field(default_factory=_empty_strings)
    # refs to ActionReasoning artifacts that were rejected this iteration
```

Rules:

- `reasoning_ref` stores the accepted `ActionReasoning` as an artifact. Like `args_redacted_ref`,
  it is a ref because reasoning text is potentially large and may contain scrubber-sensitive
  content.
- `reasoning_summary` is the `hypothesis` field inlined directly (after `scrub()`) for fast
  display without an artifact fetch.
- All reasoning text passes through `scrub()` before persistence (`architecture.md`
  scrubber rule applies — "never in a log line" for secrets).
- `rejected_reasoning_refs` captures the reasoning submitted and rejected this iteration,
  so an audit can answer: "what did the agent try to justify before it got it right?"

The audit chain now answers *why*, not just *what*:
`AgentStep → ToolInvocation.reasoning_ref → ActionReasoning`

### 5. Validator independence and the operator-vs-model asymmetry

`ActionReasoning` is **never** sent to the `validate` role. This follows the existing rule
for `CandidateFinding.reasoning` (`schemas.md:483,507`) and the `ValidatorClaim`
construction in `validation.py`. The validator receives the claim only; `ActionReasoning`
is additional hunt-private context that would correlate hunter and validator.

The asymmetry that makes live streaming safe: the independence rule forbids surfacing
reasoning to another **model** (the validator); it does not forbid surfacing it to a
**human operator** (logs, TUI). Operator-facing ≠ model-facing. Live streaming routes
reasoning to the operator, never back into any model turn.

### 6. Live reasoning streaming via `WorkflowEvent`

The agent loop emits two new iteration-grained `WorkflowEvent`s (extending the existing
stage/finding-grained event set in `schemas.md:732-752`):

- **`agent.action_proposed`** — emitted once per proposed action, after the vagueness check
  passes (or on each retry attempt). Payload: `agent_kind`, `iteration`, `tool_name`,
  `reasoning_summary` (hypothesis, post-scrub), `check_result` (passed/failed),
  `reasoning_retries` counter.
- **`agent.reasoning_rejected`** — emitted when a retry is consumed or the loop halts with
  `reasoning_rejected`. Payload: `agent_kind`, `iteration`, `tool_name`, `failed_checks`,
  `retries_remaining`.

**Emission point:** the loop already heartbeats every iteration and writes `AgentStep`. These
events are written at the same point — same code path, no extra traversal.

**Scrub-before-emit (mandatory):** `scrub()` runs on the payload before the `WorkflowEvent`
row is written. `scrubber_hits` is recorded on the event. This satisfies the
"never in a log line" rule for secrets.

**Transport:** `quarry_server` (FastAPI) exposes a poll endpoint
`GET /scans/{scan_id}/events?event_types=agent.*&after_id=...`. `quarry_client` (httpx SDK)
wraps it. The Textual TUI gains a **"worker activity"** panel polling this endpoint, rendering
each `agent.action_proposed` as:
```text
[hunt #3] reflected `q` param echoed unescaped → GET /search?q= (search.py:42) ✓
```
Rejections render in a distinct style (amber/red). Polling is the M2 baseline; SSE is a
future enhancement.

**CLI:** `quarry scan run --verbose` logs the same scrubbed reasoning events as structured
stdlib log lines. Live headless watching works without the TUI.

**Scope note:** this delivers iteration-grained TUI streaming that `week-12.md:56` deferred
("Streaming tool results back to the TUI ... not required"). This addendum makes a deliberate,
scoped reversal: we are past week 12, and live reasoning observability is the motivating use case.

### 7. Configuration keys

```toml
[scan.defaults]
reasoning_max_retries = 2          # per-action re-prompt attempts before reasoning_rejected
reasoning_min_token_length = 4     # presence check minimum per ActionReasoning slot
reasoning_strict_roles = ["prove", "dynamic_validate"]  # roles that get all four checks

[scan.reasoning_lexicon]
banned_phrases = [
    "test the exploit", "check the endpoint", "see what happens",
    "verify the vulnerability", "investigate", "probe it",
]
banned_evidence_claims = ["it works", "confirmed", "vulnerable"]
```

All keys are optional with documented defaults; existing `quarry.toml` files without them
behave as today (no reasoning field) until the week-13 addendum is implemented.

## Consequences

### Easier

- **Audit:** every `ToolInvocation` now records the agent's stated intent. Given a surprising
  finding or misbehavior, `AgentStep → ToolInvocation.reasoning_ref → ActionReasoning` shows
  exactly what the agent claimed it was testing at each step.
- **Live debugging:** an operator can watch a scan and reason about whether the agent is on the
  right track — in real time, in the TUI worker-activity panel, without waiting for the scan
  to complete.
- **Prompt quality feedback:** vague-reasoning rejections with specific feedback (which check
  failed, what to add) improve prompt quality over iterations — the per-check failure reason
  is a structured signal for prompt template refinement.
- **No extra model calls:** detection is fully deterministic; no cost increase.

### Harder

- **Prompt template updates required:** all role prompt templates in `prompts/` must include
  the `ActionReasoning` schema in their output-schema section and must instruct the model to
  fill all four fields. This is a required week-13 addendum task.
- **False positives from deterministic checks:** the lexicon and context-reference check may
  reject valid reasoning that uses unusual phrasing. The `reasoning_max_retries` re-prompt
  loop is the safety valve; the lexicon must be tuned permissively.
- **New WorkflowEvent volume:** every proposed action emits an event. For a 20-iteration
  hunt with 3 actions per turn, that is 60 events per hunt activity. The `WorkflowEvent`
  table must support this load; index on `(scan_id, event_type, created_at)`.
- **TUI polling overhead:** the worker-activity panel polls the event feed; poll interval
  must be bounded (default 2s) to avoid overloading `quarry_server`.

### Explicitly not doing

- **LLM judge for vagueness detection in M2.** Deterministic checks are the M2 implementation.
  An opt-in sampled cross-vendor reasoning judge for high-risk roles (`prove`,
  `dynamic_validate`) is **deferred to a future ADR** and noted as the escalation path if
  deterministic checks prove insufficient in practice.
- **SSE for the worker-activity feed.** Polling (`quarry_client`) is the M2 baseline. SSE
  is an enhancement for 0.3.
- **Reasoning quality scoring.** The vagueness check is binary (pass/fail per sub-check),
  not a quality score. Scoring is deferred.
- **Retroactive reasoning.** Reasoning is mandatory on new actions from the week-13 addendum
  forward. Existing `ToolInvocation` records from weeks 11–12 have null `reasoning_ref`.

## Alternatives considered

### Free-text `reasoning: str` field

Rejected. A single text field makes the vagueness check a natural-language classification
problem, requiring either a model call or extremely brittle regex. The four-slot
`ActionReasoning` structure makes specificity requirements explicit by construction —
a model that cannot fill `target_ref` with a concrete locator has no concrete locator to
report.

### LLM judge on every tool call

Rejected for M2. Doubles model calls across the entire pipeline, adds latency to every loop
iteration, and creates a potential validator-independence entanglement (if the judge is the
same provider as the hunter). Retained as the explicit future escalation path (see
Explicitly not doing).

### Halt immediately on vague reasoning (`guard_triggered`)

Rejected. Today every guard trip halts the loop. A single vague turn does not deserve
killing the entire scan; the re-prompt is cheap and often recovers the agent. Halting is
appropriate only on exhaustion (`reasoning_rejected` after `reasoning_max_retries`).

### Putting reasoning in `CandidateFinding.reasoning`

Rejected. That field is validator-blind by policy (`schemas.md:483`). Tool-call reasoning
is a different concept (intent before action, not justification of a finding) and needs
different visibility semantics.
