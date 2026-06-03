# ADR 011: Agentic harness design

## Status

Accepted

## Context

Milestone 2 requires running multi-turn model interactions to perform recon, hunt,
validate, prove, and gapfill. These loops must co-exist with the Temporal determinism
rules already in place (no I/O in workflow code) and the security posture already
established (all target content through `scrub()` and `<target_content>` tags).

The core questions:
1. Where in the stack does the loop live?
2. How do we prevent target-controlled content from hijacking instructions?
3. How do we cap cost and iteration count reliably?
4. How do we prevent tools from escaping the repository boundary?
5. What actions can each agent role take?

## Decision

**Loop-in-activity rule.** `run_agent_loop` executes inside Temporal activities only
(`quarry_activities/recon_*.py`, future `hunt_*.py`, etc.). Workflow code schedules
activities — it never calls `run_agent_loop` directly. This keeps all I/O and
non-determinism inside activities where the Temporal sandbox expects them.

**Instruction/evidence separation.** The system prompt carries developer instructions
and the scope-exclusion block. All target-controlled content (file contents, tool
output) enters only through tool call results, which are wrapped in
`<target_content>` tags after `scrub()`. The scope-exclusion block (`build_exclusion_block`)
is injected into the system message (instruction envelope), never into
`<target_content>`, so it cannot be overridden by hostile target content.

**Iteration and budget caps.** `run_agent_loop` takes `max_iterations` (default 20)
and `BudgetSpec.max_cost_usd`. After every tool-call batch the accumulated cost is
checked. When either cap fires, the loop returns immediately with
`stop_reason="max_iterations"` or `"budget_exceeded"`.

**Repo-root path restriction.** `ToolRunner` resolves every `path` input via
`Path.resolve()` + `is_relative_to(repo_root)` before passing it to the tool.
Any path that escapes the root raises `ToolSecurityError`. This is the primary defence
against prompt-injection attempts that try to read files outside the project under
analysis (e.g. `../../../.ssh/id_rsa`).

**Role allowlist.** Each `ToolSpec` declares a `roles` list. `ToolRunner.run()` checks
the current role against this list and raises `UnauthorizedToolError` if not permitted.
This prevents agents from calling tools outside their intended capability set.

**Guard taxonomy.** After every model turn, three guards run before the next iteration:
- `check_leaked_secret`: re-scrubs the model response; hits > 0 → `guard_triggered`.
- `check_schema_mismatch`: `isinstance` check against the expected response model.
- `check_unauthorized_action`: validates action kinds against `ROLE_ALLOWED_ACTION_KINDS`.

## Consequences

- All future agent stages (hunt, validate, prove, trace, gapfill) reuse the same
  `run_agent_loop` signature. The loop is the single integration point.
- Extension tools (`opengrep`, `treesitter_query`) are registered in `BUILTIN_REGISTRY`
  when available; the loop doesn't care what's in the registry.
- The `quarry.tools` entry-points loader (Week 12) can add tools without changing the loop.
- Async model clients are explicitly deferred — the loop is synchronous and runs in
  Temporal's `ThreadPoolExecutor`.
