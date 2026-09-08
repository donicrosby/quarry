## Context

Reference-alignment roadmap, Phase 3 — the MDASH pillar. Sequenced last so the
ensemble judges a pipeline that already hunts (Glasswing, shipped) and exploits
agentically (Phases 1–2).

MDASH = a tiered panel (SOTA reasoner + cheap distilled debater + independent SOTA
counterpoint), 100+ role-tuned agents, and disagreement-as-signal ("debater can't
refute → credibility ↑"); model-agnostic via "configuration flip"; CyberGym 88.45%.

Quarry today: `panel_config.py` maps role → single provider/model;
`cross_vendor_disagreement` is a recorded boolean never used as evidence weight; single
provider dep (litellm); `vendor_allowlist` and `rate_limit_rpm` are dead schema fields
(declared, never read); ADR-021 already enforces validator independence (the seed of a
debater). The `enforce_coverage_floor` / gapfill contradiction and the panel-TOML-shape
drift (documented earlier) should be reconciled here since this change touches the
panel.

## Goals / Non-Goals

**Goals:**
- Tiered roles (reasoner / debater / counterpoint) with per-tier provider, model,
  prompt regime, and caps.
- Disagreement drives a finding credibility posterior, surfaced and auditable.
- Real multi-vendor execution (Bedrock) with `vendor_allowlist` enforced fail-fast.
- Rate limiting that actually honors `rate_limit_rpm`.

**Non-Goals:**
- No pentest-loop changes (Phases 1–2). Prompt caching (`cache_control`) and
  PII-pattern config are follow-ups. No 100-agent explosion — tiers, not agent sprawl.

## Decisions

### D1: Tiers extend RoleConfig; single-model stays valid

A role gains an optional ordered set of tier entries (reasoner/debater/counterpoint),
each a `RoleConfig`-like unit. A bare single-model role is a one-entry tier — fully
backward compatible. Reconcile the TOML shape here (`[panels.<n>.roles.<role>]` vs
documented `[panel.<n>]`) rather than leaving two shapes.

### D2: Reuse ADR-021 independence for the debater

The debater is the validator's independence boundary generalized: distinct prompt
regime, cannot emit new findings, argues to refute. This builds on shipped machinery
rather than inventing a new agent kind.

### D3: Credibility posterior, not a boolean

Replace the bare `cross_vendor_disagreement` bool with a credibility signal:
debater-fails-to-refute raises it, independent disagreement is an input to it. Keep the
raw agreement/disagreement record for audit; the posterior is a derived, reported
field. Exact scoring (weights) is an open question — start simple (ordinal:
refuted / unrefuted / contested) before numeric posteriors.

### D4: Bedrock via the existing factory + litellm route

litellm already supports Bedrock; add it as a `Provider` enum member and a factory
branch with AWS auth, so cross-vendor panels genuinely span vendors. This also makes
`cross_vendor_disagreement` meaningful (currently two litellm models = "cross-vendor"
only nominally).

### D5: Rate limiting lives in dispatch, not the workflow

Token bucket per (provider, role) with an asyncio-semaphore fallback, applied in the
client/activity dispatch path (never in workflow code, preserving replay determinism —
same rule that kept the coverage-loop and prompt-storage work replay-safe). A shared
backend (e.g. Redis) is optional; in-process is the default.

### D6: vendor_allowlist enforced fail-fast at scan start

Validate every panel model's vendor against the allowlist before any model call; fail
the scan up front on violation. Turns a dead field into a real control — the same
"declared-but-dead → enforced" pattern this roadmap keeps applying.

## Risks / Trade-offs

- **[Ensemble cost multiplies model calls]** → tiers exist precisely to route
  high-volume passes to the cheap debater; rate limiting + budget caps bound spend.
- **[Credibility scoring is easy to overfit]** → start ordinal, not numeric; make the
  rule explicit and auditable; never let credibility silently drop a finding.
- **[Bedrock/AWS auth surface]** → gate behind config; keep litellm-only as the
  default; no AWS dependency unless a Bedrock model is configured.
- **[Panel TOML shape change is breaking]** → provide a compatibility read for the
  current shape, or a one-time migration of `quarry.toml`; documented.

## Migration Plan

- Tiers and rate limiting are additive/backward-compatible (single-model + unset rpm
  behave as today). Bedrock and `vendor_allowlist` are opt-in via config.
- If the TOML shape is reconciled, ship a compat reader or a documented migration.
- Rollback: single-tier panels, no debater pass, litellm-only.

## Resolved Decisions

- **Credibility model** — ordinal (refuted / contested / unrefuted), annotate/rank only,
  never auto-drops a finding. Implemented in `quarry_models/credibility.py`.
- **`enforce_coverage_floor` vs gapfill "no synthetic floor"** — the real-gap-driven
  gapfill wins. The synthetic per-class re-hunt floor (`enforce_coverage_floor`,
  ADR-021) is retired: it was never wired into the live scan path, and the iterative
  coverage loop (ADR-022) plus real-gap gapfill now own coverage. Sending a hunter
  after every vuln class when there are no real gaps burns budget for no signal. The
  orphaned function and its unit test are removed.
- **Which stages get the debater** — validate only for now (highest-volume adversarial
  pass); prove/exploitation stay single-model until there is evidence the ensemble pays
  off there too.

- **Panel TOML shape** — keep the shipped shape (`[panels.<name>.roles.<role>]` /
  `[scan_defaults]`) and update the docs, rather than migrating to the reference doc's
  `[panel.<name>]` / `[scan.defaults]` shape. Less churn, no compat reader needed.
  Tiers extend it naturally via `[[panels.<name>.roles.<role>.tiers]]`.
  `quarry.toml.example` is the authoritative documentation of the shape.
