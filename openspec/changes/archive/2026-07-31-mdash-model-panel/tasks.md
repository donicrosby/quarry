## 1. Model role tiers (TDD)

- [x] 1.1 Test: a role configured with reasoner + debater tiers dispatches each pass to its tier's model; a single-model role behaves exactly as today.
- [x] 1.2 Extend `RoleConfig`/panel to support an ordered tier set (reasoner / debater / counterpoint), each with provider, model, prompt regime, and per-role caps (`tool_call_cap`, optional extended-thinking budget); reconcile the panel TOML shape.
- [x] 1.3 Test + enforce `tool_call_cap` bounding a tier's loop.
- [x] 1.4 Run 1.1/1.3 to green.

## 2. Multi-vendor providers (TDD)

- [x] 2.1 Test: a Bedrock-configured role records the Bedrock provider on its `ModelInvocation`; a two-vendor panel records each vendor per tier (no live keys — mock/adapter-level).
- [x] 2.2 Add Bedrock to the `Provider` enum and a factory branch (litellm bedrock route + AWS auth), gated so no AWS dependency is needed unless configured.
- [x] 2.3 Test + enforce `vendor_allowlist` fail-fast before any model call; empty allowlist = unrestricted.
- [x] 2.4 Run 2.1/2.3 to green.

## 3. Model rate limiting (TDD)

- [x] 3.1 Test: calls exceeding a role's `rate_limit_rpm` are throttled to the limit; unset rpm is unthrottled; limiter is outside workflow code (replay-safe).
- [x] 3.2 Implement a per-(provider, role) token bucket with an in-process asyncio fallback in the dispatch path; wire it from `rate_limit_rpm`.
- [x] 3.3 Run 3.1 to green.

## 4. Cross-model disagreement → credibility (TDD)

- [x] 4.1 Test: a debater tier argues to refute a candidate, emits no new findings, and its failure-to-refute raises the finding's credibility; independent disagreement is recorded as a credibility input, not a bare boolean.
- [x] 4.2 Implement the debater pass (reuse ADR-021 independence) and an (ordinal-first) credibility posterior on findings; retain the raw agreement/disagreement record.
- [x] 4.3 Test + render credibility and the contributing ensemble in the report, each traceable to a provenance-tracked invocation.
- [x] 4.4 Run 4.1/4.3 to green.

## 5. Reconciliation, docs, gate

- [x] 5.1 Resolve the `enforce_coverage_floor` vs gapfill "no synthetic floor" contradiction while in the panel/validate code; record the decision.
- [x] 5.2 Document the tiered panel, disagreement/credibility model, Bedrock setup, `vendor_allowlist`, and rate limiting; update `quarry.toml.example` and reconcile the model-panel doc's TOML shape.
- [x] 5.3 Run the full suite (`task test`), `task lint`, and `task prompt-lint`; all must pass.
