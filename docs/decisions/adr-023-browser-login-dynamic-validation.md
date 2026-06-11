# ADR 023: Browser-based login and dynamic validation (Playwright)

## Status

Accepted (supersedes ADR-018's "Playwright deferred to 0.3" for the login and
dynamic-validation use case; amends ADR-017)

## Context

ADR-018 made all Milestone-2 target authentication `httpx`-based and explicitly deferred
Playwright / browser-based login to 0.3. That covers token, basic, header, cookie, and simple
POST-credential `login_flow` targets. It does **not** cover the common real case: a target whose
login is a JavaScript-rendered form, an SSO/redirect dance, a CSRF-token-embedded-in-page flow,
or a single-page app that establishes its session through browser-side script. A single `httpx`
POST cannot authenticate to those. To **actually log into a service** and then run authenticated
dynamic validation against it, Quarry needs a real browser.

Operators have a concrete, simple ask: point Quarry at a login page, hand it a username and
password, and tell it **what a successful login (or successful call) looks like** — a signal the
agent can reason about and the system can check. ADR-018's httpx-only design can't express any of
that.

This ADR pulls Playwright forward for the **login + dynamic-validation** use case only. The
static httpx auth kinds (`bearer`, `basic`, `static_header`, `cookie`, `login_flow`) are
unchanged and remain the default; `browser_login` is opt-in and heavier.

Constraints inherited unchanged from ADR-017 / ADR-018:

- The agent never sees raw secrets, the captured session, or cookies — only the profile name.
- Credential/session resolution runs **only in the `quarry-dynamic` worker / sandbox**, never in
  agent context, workflow code, or the orchestrator.
- The ADR-017 six-layer safety boundary is not relaxed; browser automation is additive on top.
- No secret values in committed files; secrets are `SecretRef(env="QUARRY_SECRET_*")` pointers.
- Login navigation is non-idempotent (ADR-017 POST rule applies).
- The scrubber must know every concrete secret and the captured session value.

## Decision

### 1. `browser_login` auth kind

Add `browser_login` to `AuthProfileKind`. It is executed via **Playwright (headless Chromium)**
inside the `quarry-dynamic` worker, or inside the egress-restricted sandbox for the prove path.
Username comes from `AuthProfile.username`; the password (and any OTP) from `SecretRef` env vars,
using the same `${username}` / `${secret:ENV}` / `${totp}` placeholders as `login_flow`.

### 2. Declarative login steps

A `BrowserLoginStep` declares the flow without embedding secrets or arbitrary code:

```
BrowserLoginStep
├── start_url          str                 login page path (host in allowed_hosts)
├── username_selector  str                 CSS/text selector for the username field
├── password_selector  str                 CSS/text selector for the password field
├── submit_selector    str                 selector for the submit control
├── otp_selector       str | None          OTP field selector (when TOTP-gated)
├── extra_steps        list[BrowserAction] pre/post actions: click | fill | wait_for (optional)
└── success            SuccessCheck         how to confirm login succeeded (see §3)
```

`fill` values use the same placeholder substitution as `login_flow`. `extra_steps` is a small,
closed vocabulary (`click`, `fill`, `wait_for`) — not arbitrary scripting — so a profile cannot
smuggle executable logic. The browser navigates only within `allowed_hosts`; any navigation that
resolves outside the allowlist aborts the login and records an `auth_failed` artifact.

### 3. Success criteria (operator-defined, code-evaluated)

This is the "what the model should look for for a successful call" piece. A `SuccessCheck`
declares the signal that confirms success:

```
SuccessCheck
├── kind     Literal["url_matches","selector_present","text_present","status_ok"]
├── value    str          # url substring | CSS selector | expected text | (status: unused)
└── description str        # human-readable, surfaced to the agent for reasoning
```

An optional negative `failure_check: SuccessCheck | None` lets a profile declare an explicit
failure signal (e.g. an error banner selector) to fail fast rather than wait for a timeout.

Crucially: the check is **evaluated deterministically in code** after the login (or dynamic)
action — the verdict is not the model's say-so. The `description` is surfaced to the
`dynamic_validate` / `prove` agent so it can reason about what success looks like, but the gate
that decides "logged in" / "call succeeded" is code, consistent with validator-independence and
the "never trust the model for a safety or verdict decision" rule. This same `SuccessCheck`
mechanism is reused for non-login dynamic-validation actions: an operator can declare what a
successful exploited/authenticated call looks like (e.g. `text_present` = the *other* user's
email for an IDOR check), giving the dynamic path a deterministic oracle.

### 4. Session capture and reuse

On a passing `SuccessCheck`, the worker captures Playwright **storage state** (cookies +
localStorage) as the session. Subsequent dynamic requests reuse it — either driven through the
same browser context, or by exporting the session cookies into the existing `httpx` dynamic path
for plain HTTP probes. The captured storage state is treated exactly like a resolved credential:
registered in the per-run scrubber denylist, held in the in-memory `CredentialCache`
(TTL + 401/failure re-login), **never persisted**, **never returned to the agent**. The report
records only `auth_profile_used` (the name).

### 5. Safety and isolation

The browser executes the target's JavaScript, so it is the highest-risk component in the dynamic
path and runs **only** inside the sandbox / `quarry-dynamic` worker with:

- Egress pinned to the authorized target host(s) (K8s `NetworkPolicy` allow-list / Docker network
  attachment from ADR-017 / week-14.5); no host network, no service-account token, ephemeral
  browser profile dir, `readOnlyRootFilesystem` where possible.
- The ADR-017 six layers all enforced before any navigation; the scope-exclusion hard-guard
  (`do_not_test`, `block_dynamic`) evaluated against the **resolved navigation URL**.
- Login navigation non-retryable beyond the single 401/failed-login re-login (ADR-017 POST rule).

### 6. Resolution flow

Same shape as ADR-018 §4, with the `login_flow` branch generalized: for `browser_login`, on cache
miss/expiry/401, launch headless Chromium in the sandbox, run `BrowserLoginStep`, evaluate
`SuccessCheck`; on pass, capture storage state, register it in the scrubber denylist, cache it; on
fail, record `auth_failed` and mark the finding `needs_manual_review`. The agent only ever
proposes `HttpRequestSpec(auth_profile="…")` and never sees the browser, the session, or cookies.

## Consequences

### Easier

- Quarry can authenticate to real SPA/SSO/JS-driven targets and run authenticated dynamic
  validation against them — the main limitation of the httpx-only design is removed.
- Operators declare success signals declaratively; the dynamic path gets a deterministic oracle
  (login *and* exploit-confirmation) instead of trusting model narration.

### Harder

- Playwright is a heavy dependency (browser binaries, hundreds of MB) — it must be baked into the
  sandbox image and is not part of the default install. The non-browser path must not require it.
- A real browser running untrusted target JS is a large attack surface; it is only acceptable
  inside the egress-pinned sandbox. This couples `browser_login` to the week-14.5 sandbox work.
- Browser login is slower and non-deterministic; flakiness (selectors, timing) is expected and
  must be bounded by explicit `wait_for` + `SuccessCheck`/`failure_check`, not arbitrary sleeps.
- Captured storage state is a new secret surface (it *is* the session) — scrubber registration and
  the never-persist rule must cover it as strictly as a bearer token.

### Explicitly not doing

- Full OAuth 2.0 / OIDC authorization-code + PKCE automation beyond what the declarative steps
  express. (Still a 0.3 candidate; `browser_login` covers form/SSO logins reachable by selector.)
- Non-Chromium browsers; visual/screenshot-diff success signals (M2 success checks are
  url/selector/text/status only).
- Using the browser for the static auth kinds — `bearer`/`basic`/`static_header`/`cookie`/
  `login_flow` remain `httpx`-based and are still the default.
- Arbitrary scripting in profiles — `extra_steps` is a closed action vocabulary, never raw JS.

## Alternatives considered

### Keep ADR-018's httpx-only deferral

Rejected per operator requirement: real targets log in through the browser. An httpx-only design
cannot reach behind JS/SSO logins, which is most authenticated app surface worth testing.

### Let the model drive the browser directly (agent issues click/type tool calls)

Rejected. Giving the agent live browser control inside an authenticated session widens the blast
radius and breaks the "agent never sees the session" invariant. The login is declarative and
worker-side; the agent only proposes named-profile HTTP specs.

### Trust the model to decide login/call success

Rejected. Success is a verdict; verdicts are code-evaluated (validator-independence). The model is
given the `SuccessCheck.description` to reason with, but the deterministic check is the gate.

### Screenshot/vision-based success detection

Deferred. Adds a vision model dependency and non-determinism; url/selector/text/status checks
cover the common cases in M2.
