## Why

Quarry is ~40% of MDASH: it has a model panel (role → provider/model), a
`cross_vendor_disagreement` flag, domain-context plugins, and best-in-class
multi-model provenance — but the *ensemble semantics* that make MDASH work are absent.
MDASH runs a tiered panel (a SOTA "heavy reasoner," a cheap distilled "debater" for
high-volume passes, and a second independent SOTA "counterpoint") and treats
disagreement as evidence: "when an auditor flags something and the debater can't
refute it, that finding's posterior credibility goes up." Quarry *records* vendor
disagreement as a boolean on a report and never uses it. It also runs a single
provider dependency (litellm only) with no Bedrock and with `vendor_allowlist` /
`rate_limit_rpm` present as dead schema fields.

This is Phase 3 of the reference-alignment roadmap: turn the existing panel into an
MDASH-style ensemble — tiered roles, disagreement-as-signal feeding finding
credibility, real multi-vendor execution, and the rate limiting that real multi-vendor
demands. Combined with the shipped multi-model provenance, this is the differentiator:
an ensemble whose every judgement is reproducible to the exact model and prompt.

## What Changes

- **Model role tiers**: extend the panel so a role can be served by a tier —
  SOTA reasoner, cheap distilled debater, independent SOTA counterpoint — with each
  tier carrying its own provider/model, prompt regime, and caps (`tool_call_cap`,
  `extended_thinking`/`thinking_budget_tokens`, the currently-absent per-role knobs).
- **Disagreement-as-signal**: a debater tier argues *against* a candidate's
  reachability/exploitability; when it cannot refute, the finding's credibility rises;
  when independent models disagree, that is recorded as a credibility input, not a
  discarded boolean. Findings carry a credibility posterior derived from ensemble
  agreement, surfaced in the report.
- **Real multi-vendor**: add the Bedrock provider and make cross-vendor panels
  actually run across vendors; enforce `vendor_allowlist` fail-fast before any model
  call (activating the dead field).
- **Model rate limiting**: enforce `rate_limit_rpm` per (provider, role) with a token
  bucket and an asyncio-semaphore fallback (activating the dead field), so multi-vendor
  runs respect provider limits instead of recording an rpm nobody honors.

Non-goals: no change to the pentest loops (Phases 1–2); no new vuln taxonomy. Prompt
caching (`cache_control`) and PII-pattern config are noted as follow-ups, not in scope.

## Capabilities

### New Capabilities
- `model-role-tiers`: a role may be served by a configured tier of models (SOTA
  reasoner / distilled debater / independent SOTA counterpoint), each with its own
  provider, model, prompt regime, and per-role caps.
- `cross-model-disagreement`: ensemble disagreement is a first-class credibility
  signal — a debater's failure to refute raises a finding's credibility posterior, and
  the posterior is recorded and reported.
- `multi-vendor-providers`: real execution across vendors including Bedrock, with
  `vendor_allowlist` enforced fail-fast before any model call.
- `model-rate-limiting`: per-(provider, role) rate limiting (token bucket + asyncio
  fallback) enforced from `rate_limit_rpm`, replacing the currently-recorded-but-unused
  value.

### Modified Capabilities
<!-- No existing openspec/specs/ capability is rewritten; this builds on the shipped
     loop-invocation-provenance / model-prompt-storage provenance and the existing
     panel_config. -->

## Impact

- **Code**: `panel_config.py` / `panel.py` (tiered `RoleConfig`, per-role caps);
  `factory.py` (Bedrock client via litellm's bedrock route + AWS auth); a debater
  pass in validate/prove; a credibility field on findings + report rendering; a rate
  limiter around model dispatch; `vendor_allowlist` enforcement at scan start.
- **Config**: reconcile the panel TOML shape (shipped `[panels.<n>.roles.<role>]` /
  `[scan_defaults]` vs the documented `[panel.<n>]` / `[scan.defaults]`, and the
  documented `oss`/`bedrock`/`benchmark` panels) as part of adding tiers.
- **Provenance**: each tier's calls are already provenance-tracked; the credibility
  posterior records which models agreed/disagreed, so a verdict is auditable to the
  ensemble that produced it.
- **Cost/limits**: rate limiting prevents multi-vendor runs from tripping provider
  limits; tiering lets high-volume passes use the cheap debater.
- **Depends on**: independent of Phases 0–2 in principle, but sequenced last so the
  ensemble judges a pipeline that already hunts and exploits agentically.
