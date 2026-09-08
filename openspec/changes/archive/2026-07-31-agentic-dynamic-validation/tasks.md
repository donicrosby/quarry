## 1. Dynamic-validation prompt family

- [x] 1.1 Add a generic `prompts/dynamic_validate/dynamic_validate.1.0.0.j2` template (four-part envelope) instructing the agent to corroborate one candidate hypothesis against the live target via `http_request`, and to return a live verdict + cited evidence.
- [x] 1.2 Add per-class templates for the high-value classes (at least IDOR, command_injection, SSRF); wire `resolve_prompts()` startup validation and `prompt-lint`.

## 2. Agentic dynamic-validation activity (TDD)

- [x] 2.1 Write a unit test: given a validated candidate + a mock client that proposes an `http_request` and then a verdict, the activity returns a `corroborated` result with linked HTTP evidence; and an `inconclusive` result when responses are ambiguous.
- [x] 2.2 Implement the activity on `run_agent_loop` in the `dynamic_validate` role, selecting the per-class (or generic) template, passing `PromptProvenance` and the real scan_id, and mapping the loop's final answer to a live verdict.
- [x] 2.3 Capture request/response pairs as evidence artifacts linked to the finding (reuse `DynamicEvidenceLink` / HTTP capture); assert no credentials appear in stored prompts.
- [x] 2.4 Register the activity in `quarry_worker/main.py` and `quarry_server/app.py` (dual-worker rule); run 2.1 to green.

## 3. Safety-guard coverage (TDD)

- [x] 3.1 Test that an `http_request` to a host outside `allowed_hosts` is refused before I/O, and that an empty allowlist blocks all requests (fail-closed).
- [x] 3.2 Test that scope exclusions and `block_dynamic` are honored, and that credentials are injected via the cache and never rendered into prompts.

## 4. Pipeline stage wiring (TDD)

- [x] 4.1 Write an integration test: with `--dynamic-validation` + a target, the stage runs after validate and before prove and annotates findings with a live verdict; without the flag it is a no-op and no `http_request` is sent; flag-without-target is rejected at launch.
- [x] 4.2 Add the `dynamic_validate` stage to `RunScanWorkflow` between validate and prove, gated on the flag + resolved target; thread the live verdict to the prove stage's prioritization.
- [x] 4.3 Run 4.1 to green.

## 5. Docs and gate

- [x] 5.1 Document the dynamic-validation stage, the prompt family, and the fail-closed authorization model (extend the relevant docs / ADR-017 notes).
- [x] 5.2 Run the full suite (`task test`), `task lint`, and `task prompt-lint`; all must pass.
