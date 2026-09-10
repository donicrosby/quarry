## Why

Candidate sourcing is agentic-only across 17 hunt classes (ADR-013), but the
dynamic-validation side has not kept pace: per-class `prompts/dynamic_validate/`
templates exist only for idor, command_injection, and ssrf plus a generic
fallback, and `live_verdict_from_status()` maps status codes generically. Many
classes need body-content or differential verdicts (SQLi response diffing,
SSTI marker evaluation) rather than status-code heuristics.

The result: huntable classes cannot be dynamically validated with class-specific
rigor, and verdict logic is hardcoded where ADR-017 expects code-evaluated,
per-class purity.

## What Changes

- **Per-class dynamic_validate prompts.** Add templates under
  `prompts/dynamic_validate/` for every huntable class: sql_injection, xss,
  ssti, xxe, file_upload, auth, open_redirect, csrf (and confirm the existing
  idor / command_injection / ssrf set). Extends `agentic-dynamic-validation`.
- **VerdictEvaluator registry.** Introduce a per-class registry of pure
  verdict functions (response-diffing, marker evaluation, status mapping)
  replacing hardcoded if/else in the validation path, satisfying ADR-017's
  "code-evaluated" rule per class. Extends `dynamic-validation-live-http`.
- **Missing hunt templates.** Add hunt templates for xxe, file_upload, csrf so
  every `VulnerabilityClass` enum member is huntable. Extends `hunt-stage`.

## Impact

- Affected specs: `agentic-dynamic-validation`, `dynamic-validation-live-http`, `hunt-stage`
- Affected code: `prompts/dynamic_validate/*.j2`, `prompts/hunt/*.j2`,
  new `src/quarry_activities/verdict_evaluators.py`, wiring in
  `src/quarry_workflows/run_scan.py` (replace `live_verdict_from_status` hardcoding)
- Board tickets: t_b4b0a2ab

## Non-goals

- Browser-backed XSS/DOM confirmation (Slice 2, needs the browser driver).
- Canary/callback listener for SSRF/XXE OOB proof (separate infra ticket).
- Multipart request forging (W5) — file_upload validation is limited to what
  the current HttpRequestSpec supports until that lands.
