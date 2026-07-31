# ADR 017: Opt-in live dynamic exploitation and validation

## Status

Accepted

## Context

Keygraph Shannon, one of Quarry's three primary reference systems, is defined by "white-box
source-aware analysis drives attack strategy, then live dynamic exploitation validates findings.
Works across languages (Node.js, Python, Go)." (`docs/architecture.md:33-37`, `:111-127`).

Milestone 2 (weeks 11 to 17) converts all 8 pipeline stages to agents and delivers the
source-aware half well. However, the entire find-to-prove path remains static and network-isolated:

- `validate` (week 13) is `read_file`/`grep` only; the week-13 plan lists "Validator accessing
  the internet or external tooling" under *Not required*.
- `prove` (week 14) runs PoC code in a `--network none` / deny-all-egress sandbox; the week-14
  plan says "Safe triggering inputs only — nothing that touches the network."
- No agent tool can issue an HTTP request. The `quarry-dynamic` task queue exists but no
  agent uses it.
- `httpx` and Playwright are listed in the recommended stack as "later" (`architecture.md:373`).
- Milestone 1 included a narrow source-to-dynamic correlation for IDOR and command injection
  (validation request → proof response against a local target URL), but this did not carry
  into the Milestone 2 agentic harness. Milestone 2 actually regresses on live validation
  relative to Milestone 1.

Without a live dynamic path Quarry cannot reach Shannon parity: the "source-aware + live dynamic"
shape that defines Shannon's practical value is absent.

The docs explicitly caution "Do not assume live exploitation is always safe" (`architecture.md:132`).
Live HTTP against an uncontrolled host could cause data loss, rate limiting, or TOS violations.
It must never be the default.

Most of the needed infrastructure already exists in the design:

- `ScopeExclusion.block_dynamic` and `TargetAuthorization.do_not_test` are in `schemas.md`.
- `ScanProfile.dynamic_validation_enabled` and `proof_enabled` both default to `False`.
- `ArtifactKind.HTTP_REQUEST` and `HTTP_RESPONSE` are defined.
- `ValidationResult.evidence_refs` and `ProofArtifact.evidence_refs` already exist to hold
  HTTP request/response artifacts.
- `SandboxBackend.run(..., target_endpoint: TargetEndpoint | None = ...)` is referenced in
  ADR-011's K8s NetworkPolicy clause ("deny all egress except to the target service on its
  specific port"). The `TargetEndpoint` parameter is assumed but was never formally defined.
- The week-14 `ToolRunner` hard-guard pattern (scope-exclusion check → refused `ToolInvocation`
  with `allowed=False`, `denied_reason`, `status="refused"`) is the right pattern for dynamic
  requests; it was designed for the `run_in_sandbox` tool but applies equally here.
- The `quarry-dynamic` task queue is the intended queue for this class of work.

This is therefore mostly a wiring and one-new-tool exercise, not a schema redesign.

## Decision

Add an opt-in, scope-gated live dynamic exploitation and validation path to Milestone 2.
It is entirely additive: with no `target_url` or when either gate flag is off, the pipeline
behaves exactly as today.

### 1. Safety boundary — six independent layers, all required

A live HTTP request may be sent only when **all** of the following hold. These are independent
enforcement layers; satisfying five of six is not enough.

**Layer 1 — Config gate.** `ScanProfile.dynamic_validation_enabled = True` (for dynamic
validate) and/or `proof_enabled = True` with a live-mode flag (for prove). Both default
to `False`. No flag, no live traffic; the pipeline runs static + isolated-sandbox PoC as today.
CLI: `--dynamic-validation` / `--live-prove` (both off by default). If either live flag is on
and `target_url` + `allowed_hosts` + a non-expired `TargetAuthorization` are absent, raise a
clear startup error before any model call (`resolve_dynamic()` analogous to `resolve_focus()`).

**Layer 2 — Target gate.** `Target.target_url` is set AND `Target.allowed_hosts` is non-empty.
The `allowed_hosts` list is the complete set of hosts the scanner may contact; no request may
leave for any host outside it.

**Layer 3 — Authorization ceiling.** A `TargetAuthorization` exists, is not expired, and the
request's resolved host is in `allowed_hosts`. `TargetAuthorization.do_not_test` is a hard
ceiling the scan profile may not widen past. The authorization owner (not the scanner operator)
controls what is off-limits.

**Layer 4 — Scope-exclusion hard-guard (reuse week-14 pattern verbatim).** Before any
`http_request` tool call executes, `ToolRunner` checks the resolved request URL, functional
area, path-glob, and vuln_class against the active exclusion set — the union of
`ScanProfile.scope_exclusions` and `TargetAuthorization.do_not_test` converted to exclusion
entries, filtered to items with `block_dynamic = True`. On any match: do not send the request;
record a refused `ToolInvocation(allowed=False, denied_reason="<matching value and kind>",
status="refused")`. Never silently drop a blocked attempt. The week-14 guard already covers
`kind="route"`, `kind="functional_area"`, and `kind="path_glob"`; extend it to also evaluate
the resolved request URL (so a `path_glob` entry like `src/billing/**` that maps to a URL
prefix `/billing/` is caught) and `kind="vuln_class"` (so a vuln_class exclusion also blocks
dynamic actions for that class).

**Layer 5 — Role gate.** The `http_request` tool is registered for the `dynamic_validate` and
`prove` roles only. It never appears in the tool catalogs for `recon`, `hunt`, `gapfill`,
`validate`, `trace`, or `report`. Enforced in `registry.py` and re-checked against
`ROLE_ALLOWED_ACTION_KINDS` in `run_agent_loop`.

**Layer 6 — Network containment.** Live requests run inside a Temporal activity on the
`quarry-dynamic` task queue, not in workflow code or agent code directly. For the `prove`
role, live requests additionally run inside the egress-restricted sandbox (see ADR-011). No
agent loop, no workflow code, and no `ToolRunner` method ever opens a socket directly.

**Untrusted-evidence handling (cross-cutting).** Every HTTP response is target-controlled
content. It passes through `scrub()` and is wrapped in `<target_content>` tags before re-
entering any prompt — identical to every other tool result. Scripts are stripped from HTML
responses. Body size is capped before any processing. `scrubber_hits` on the `HttpResponseCapture`
records how many secrets patterns fired.

If any of the six layers is unsatisfied, the live path is inert and the stage falls back to its
current static/sandbox behavior. This is the backward-compatibility guarantee.

### 2. New schemas

Add to `src/quarry/schemas.py` (Milestone 2 block):

**`TargetEndpoint`** — the single host:port the egress policy permits. Built once at scan start
from `Target.target_url` + `allowed_hosts`; resolved to an IP so K8s NetworkPolicy and the
Docker allowlist can be pinned to an IP rather than a DNS name:

```python
class TargetEndpoint(BaseModel):
    host: str
    port: int
    scheme: Literal["http", "https"] = "http"
    base_path: str = "/"
```

**`HttpRequestSpec`** — the request the agent proposes; carries no inline secrets:

```python
class HttpRequestSpec(BaseModel):
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    path: str                    # relative to TargetEndpoint.base_path
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    auth_profile: str | None = None  # named cred from Target.auth_config_ref; never inline
```

**`HttpResponseCapture`** — the captured response, with the body stored as an artifact (not
inline) to keep responses out of the domain model and through the artifact store:

```python
class HttpResponseCapture(BaseModel):
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body_artifact_ref: str       # ArtifactRef id for the scrubbed, size-limited body
    elapsed_ms: int
    scrubber_hits: int = 0
    redaction_status: RedactionStatus
```

**`DynamicEvidenceLink`** — the static-to-dynamic correlation chain, making explicit the
`source → route → request → response → finding` provenance required by reference-alignment.md:54:

```python
class DynamicEvidenceLink(BaseModel):
    source_ref: SourceRef              # white-box anchor: file, line
    attack_surface_item_id: str | None = None  # the route or entry point
    request_artifact_id: str           # ArtifactRef id for HTTP_REQUEST
    response_artifact_id: str          # ArtifactRef id for HTTP_RESPONSE
    candidate_finding_id: str
```

`ValidationResult` and `ProofArtifact` require no schema changes — they already carry
`evidence_refs` for HTTP_REQUEST/RESPONSE artifacts. The new artifacts attach there.
`DynamicEvidenceLink` rows attach as structured entries in `metadata` or `evidence_refs`.

Extend `AgentStep.agent_kind` to include `"dynamic_validate"` alongside `"orchestrator"`,
`"subsystem"`, `"synthesis"`, `"hunt"`, `"validate"`, `"prove"`, `"trace"`, `"gapfill"`.

### 3. New `dynamic_validate` role (distinct from `validate`)

Add `dynamic_validate` to the role system (`ModelPanelEntry.role`, `RoleConfig`, the panel
configuration, and `ROLE_ALLOWED_ACTION_KINDS`). This is distinct from the static `validate`
role for two reasons:

First, static `validate` must stay network-free to preserve the adversarial-review design from
week 13: the validator's independence (receiving only the claim, never the hunter's reasoning or
tool trace) is the cornerstone of Quarry's noise-reduction architecture. Giving the same role
network access would conflate two concerns that must remain separated.

Second, the cross-vendor panel logic uses the `validate` role to select a different provider
than `hunt` for adversarial disagreement. `dynamic_validate` can share that constraint (default
to a different provider than `hunt`) without contaminating static `validate`.

The `dynamic_validate` role does non-destructive corroboration: confirm an IDOR exists by
fetching another user's object with a legitimate token; confirm a command injection path is
reachable by observing a harmless side effect. It does not receive the hunter's reasoning chain.

### 4. New tool: `http_request` (`src/quarry_tools/http_tool.py`)

`ToolSpec(name="http_request", roles={"dynamic_validate", "prove"}, input_schema=HttpRequestSpec)`.
Built on `httpx` (already in the recommended stack as a dynamic helper).

The tool never opens a socket in agent context. `ToolRunner` receives the spec, confirms all
six safety layers are satisfied, and dispatches to the appropriate path: for `dynamic_validate`,
a `quarry-dynamic` activity worker with `Target.allowed_hosts` enforced; for `prove`, the
sandbox with `TargetEndpoint`-gated egress.

Register in `src/quarry_tools/registry.py`. Never register for any other role.

### 5. Sandbox and network model (augmenting ADR-011)

`SandboxBackend.run` already accepts `target_endpoint: TargetEndpoint | None`. Threading a
non-`None` value is what flips the sandbox from "isolated PoC" to "live exploitation."

`K8sJobSandbox`: keep deny-all egress when `target_endpoint is None` (today's default). When
set, add a single egress allow to `TargetEndpoint.host:port` (resolve to IP at activity setup;
DNS stays denied; pin the NetworkPolicy to the IP). All hard manifest properties from
ADR-011 are unchanged.

`LocalDockerSandbox`: default stays `--network none`. Live mode attaches to a Docker network
containing only the target service. Note that Docker Desktop on macOS does not enforce network
isolation as strictly as K8s NetworkPolicy — the local backend is for wiring tests only.
The production-grade network guarantee is K8s NetworkPolicy.

**Prove-sandbox credential injection (ADR-018):** The egress-restricted sandbox cannot call
back to the `quarry-dynamic` worker at execution time. When an `auth_profile` is set on the
`HttpRequestSpec`, the prove activity resolves the credential worker-side first (reusing the
per-run `CredentialCache` — a single login/TOTP occurs per TTL period), then injects the
already-resolved concrete credential as `QUARRY_INJECTED_CRED_<profile_name>` env var into
the sandbox job spec. The in-sandbox `http_request` helper attaches it by profile name. The
prove agent still only sees the profile name. The resolved value is registered in the per-run
scrubber denylist before injection.

### 6. Temporal placement

`http_request` runs inside a Temporal activity on the `quarry-dynamic` queue, never in workflow
code or the agent loop directly. The prove agent's live requests are additionally contained
inside the sandbox. This preserves Temporal's determinism rules from ADR-014.

Non-idempotent HTTP methods (POST, PUT, DELETE) are not automatically retried on the Temporal
level for the dynamic activity. Mark the activity as non-retryable for those methods, or require
an explicit idempotency key, to avoid duplicate side effects against the target. GET is
retry-safe.

### 7. Proof capture

Live-validated findings record a `ValidationResult` whose `evidence_refs` include HTTP_REQUEST
and HTTP_RESPONSE artifacts, plus a `DynamicEvidenceLink` row tying `source_ref → route →
request → response → finding`.

Live-proved findings record a `ProofArtifact(proof_type="dynamic_http")` with `safe_payload`
set and request/response artifacts in `evidence_refs`.

`FinalFinding.proof_artifact_ids` must be non-empty for any finding promoted via the live path.
The existing "only final findings with proof appear in reports" rule is unchanged; live dynamic
is a stronger proof source, not a relaxation.

### 8. Config (quarry.toml + CLI)

Reuse `dynamic_validation_enabled` and `proof_enabled` (already in `ScanProfile`, both default
`False`). Surface as `--dynamic-validation` and `--live-prove` CLI flags (both off by default).
`--target-url` is required when either is on. Add `resolve_dynamic()` startup validation (like
`resolve_focus()`) that fails fast with a clear error if a live flag is on without `target_url`,
`allowed_hosts`, and a non-expired `TargetAuthorization`.

Add `dynamic_validate` to `quarry.toml.example`'s panel section. Recommend a cross-vendor model
(different provider than `hunt`).

Credentials for the target are managed by ADR-018 (target authentication and credential
resolution). `Target.auth_config_ref` points to an `auth-profiles.toml` file containing
`AuthProfile` declarations; secret values are `SecretRef` env-var pointers, never inline.
Profiles are loaded and validated at scan start by `resolve_auth()`. Credential resolution
occurs inside the `quarry-dynamic` worker at activity dispatch time — never in agent context,
workflow code, or the `ToolRunner` orchestrator process. The agent proposes only the profile
name in `HttpRequestSpec.auth_profile`; the concrete credential is never returned to it.

### 9. M1 static-dynamic correlation restored

This path re-homes Milestone 1's source-to-dynamic correlation into the agentic harness. In
Milestone 1, a static IDOR finding caused an httpx probe to be sent and the response captured,
forming a `source → route → request → response → finding` chain. That chain was not carried
into Milestone 2's agentic pipeline. The `DynamicEvidenceLink` schema and the `http_request`
tool restore this chain as a first-class concept, making it available to any vulnerability class
that can benefit from live corroboration.

## Consequences

### Easier

- Quarry matches Shannon's "source-aware + live dynamic" shape. Shannon parity on this dimension
  is achieved.
- The existing `vulnerable-fastapi` example (which already has a `target_url`) is a natural
  Shannon-parity demo target with no additional infrastructure.
- The static pipeline's backward compatibility is complete: no live flag, no live traffic.
- The six-layer safety boundary means each layer can be independently tested and audited.
- The adversarial `validate` role remains network-free, preserving its independence guarantee.
- M1's static-dynamic correlation chain (`source → route → request → response → finding`) is
  restored in the agentic harness via `DynamicEvidenceLink`.

### Harder

- The `quarry-dynamic` worker must enforce `allowed_hosts` independently of the scan config.
  This is an additional enforcement surface that must be tested.
- The `K8sJobSandbox` now has two modes (isolated PoC vs. live egress). The mode is data-driven
  (`target_endpoint` presence), but the distinction must be explicit in tests.
- Non-idempotent HTTP methods require care around Temporal retries. Every dynamic activity for
  POST/PUT/DELETE must be explicitly non-retryable or carry an idempotency key.
- The `http_request` tool's response handling (scrub + cap + artifact store) adds latency to
  the agent loop for dynamic-validate and prove roles.
- Prompt injection blast radius for the `dynamic_validate` and `prove` roles grows: HTTP
  response bodies are attacker-controlled. The `<target_content>` boundary and `scrub()` are
  mandatory — there is no fallback.

### Explicitly not doing

- Playwright/browser automation. That is a 0.3 candidate. The `http_request` tool covers the
  live HTTP surface for M2.
- Networked execution from recon, hunt, gapfill, trace, or report roles. The live path is
  strictly `dynamic_validate` and `prove` only.
- Relaxing the adversarial validator's static-only, claim-only design. The static `validate`
  role is unchanged.
- Allowing public internet targets. `allowed_hosts` is required; the default behavior blocks
  anything not in the list.
- Real Slack/Jira live integrations in the same week. Those remain in the 0.2 candidates.

## Alternatives considered

### Extend the static `validate` role with optional network access

Rejected. Mixing static adversarial review with live HTTP access would contaminate the
validator-independence design from week 13 (the validator must see only the claim, not the
hunter reasoning or tooling). A separate `dynamic_validate` role preserves the boundary cleanly
and allows different panel routing.

### Make live validation always enabled when a target URL is present

Rejected. A target URL is needed for some static-plus-sandbox-PoC workflows too (e.g. confirming
a route exists). Conflating URL-present with live-enabled removes operator control and could cause
unintended live traffic during what the operator intended as a static scan.

### Implement live dynamic using Playwright from the start

Rejected for M2. Browser automation adds significant infrastructure (Playwright install, headless
browser process, DOM parsing) that is disproportionate to the M2 scope. `httpx` covers the live
HTTP surface needed for IDOR, command injection, and SSRF corroboration. Playwright is a 0.3
candidate.

### Put live requests on the `quarry-proof` queue instead of `quarry-dynamic`

Rejected. The `quarry-proof` queue is rate-limited and isolated for sandbox execution; adding
dynamic requests would expand its network surface area beyond its intended scope. `quarry-dynamic`
is the existing intended queue for `httpx` and target checks (`architecture.md:691`).

## Implementation notes: the agentic `dynamic_validate` stage

The `dynamic_validate` seat provisioned above is now filled by a real agent. The seam
between "agent decides" and "workflow acts" follows the same "agent proposes → workflow
dispatches" contract the `prove` stage uses (Option A). This keeps every socket-opening
operation inside a Temporal activity and off both the workflow and the agent loop.

### Stage placement and gating

The stage runs inside `AGENTIC_VALIDATE` for each finding the static validator returns as
`needs_proof` / `inconclusive`, after the validate verdict and before `PROVE`. It is active
only when `dynamic_validation_enabled` is set AND a `target_url` is resolved — the pure
predicate `dynamic_validation_active(enabled, target_url)`
(`src/quarry_workflows/dynamic_validate_stage.py`). Target presence alone never enables live
traffic. When the predicate is false the stage is a no-op: no `dynamic-validate-finding`
activity runs and no `http_request` is dispatched, so the pipeline behaves exactly as it did
before this change (the backward-compatibility guarantee in Decision §1).

`--dynamic-validation` without a target is rejected before any model call by the config gate
(`resolve_dynamic()`) and the CLI guard, per Decision §8.

### Agent proposes, workflow dispatches

1. `dynamic_validate_activity` (`name="dynamic-validate-finding"`, registered in both
   `quarry_worker/main.py` and `quarry_server/app.py`) runs `run_agent_loop` in the
   `dynamic_validate` role with a no-I/O `http_request` tool. The agent returns a
   `DynamicValidateResponse` carrying `proposed_http_specs` and a verdict; it never opens a
   socket.
2. The workflow selects the spec to send via `select_dynamic_probe_spec()`: the first
   well-formed agent proposal, falling back to the deterministic per-class probe
   (`build_dynamic_probe_spec`) when the agent proposed nothing usable. Malformed proposals
   (e.g. inline auth rejected by `HttpRequestSpec`) are skipped, not fatal.
3. The workflow performs the single egress via the `http-request` activity
   (`RetryPolicy(maximum_attempts=1)` — non-idempotent methods are never auto-retried,
   Decision §6) and maps the capture to a live verdict with the pure helper
   `live_verdict_from_status()`:
   - `2xx` → `corroborated`
   - `401` / `403` / `404` → `not_corroborated` (target enforces the guard)
   - anything else (5xx, ambiguous) → `inconclusive`
4. A `corroborated` result promotes the finding to a `FinalFinding` with non-empty
   `proof_artifact_ids` and a `DynamicEvidenceLink` (`promote_with_dynamic_evidence`). Any
   other verdict keeps the finding `NEEDS_PROOF`, annotated with `metadata["live_verdict"]`.
5. `PROVE` orders its queue with `prioritize_by_live_verdict()`: live-corroborated leads are
   proved first, then unannotated / inconclusive, then target-defended. The sort is stable.

### Prompt family

Templates live under `prompts/dynamic_validate/` using the four-part envelope. A generic
`dynamic_validate.1.0.0.j2` ("Live Corroboration Specialist") plus per-class specializations
for the high-value classes (`idor`, `command_injection`, `ssrf`) select via `build_prompt`
with a `TemplateNotFoundError` fallback to the generic template. `resolve_prompts()` startup
validation and `prompt-lint` cover the whole family. The per-class prompts instruct
non-destructive corroboration only — IDOR reads another principal's object; command injection
uses a benign marker payload; SSRF uses a safe allow-listed canary URL.

### Fail-closed authorization, as built

All six layers from Decision §1 apply to the `dynamic_validate` seat and are locked in by
`tests/unit/test_dynamic_validate_safety.py` against the real tool registry:

- **Role gate** — `http_request` is registered for `dynamic_validate` (and `prove`) only.
- **allowed_hosts fail-closed** — an empty allowlist refuses every request before I/O; an
  out-of-scope host is refused with a `denied_reason` and no capture.
- **Scope exclusions / `block_dynamic`** — a matching `block_dynamic` route is refused; a
  non-`block_dynamic` exclusion does not block.
- **Credentials** — an unknown `auth_profile` is refused; a known one passes. The agent only
  ever sees a profile NAME. Even with a live secret in the environment, no persisted seed
  prompt or artifact contains the secret value (credentials are injected worker-side at
  dispatch, per ADR-018).

Every HTTP response remains target-controlled content: it passes through `scrub()` and the
`<target_content>` boundary before re-entering any prompt (the cross-cutting rule in
Decision §1).
