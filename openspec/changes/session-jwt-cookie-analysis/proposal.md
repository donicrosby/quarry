# Proposal: session-jwt-cookie-analysis

## Why

The codebase can authenticate to targets (bearer tokens, cookies, login flows, browser
automation) and the `AUTH` vulnerability class hunt already instructs the LLM agent to
look for weak session/JWT patterns. But the LLM sees only source code — it cannot
inspect the ACTUAL tokens and cookies the target emits at runtime. A JWT signing
algorithm trivially downgraded to `none`, or a session cookie missing `HttpOnly` and
`Secure`, is invisible to code-level analysis and becomes a blind spot.

This change adds a deterministic, code-driven session-token analyzer that hooks into the
live HTTP pipeline: every auth-related response (login, token issuance, cookie-set) is
inspected for a configurable checklist of security properties, and any failing check
becomes a candidate finding under the `AUTH` vulnerability class.

## What Changes

- ADDED capability `auth-session-analysis`: a **SessionTokenAnalyzer** that extracts
  JWTs and session cookies from auth-related HTTP responses (multi-value Set-Cookie
  read from the raw response headers before dict collapse), evaluates them against
  a checklist of security properties, and emits `CandidateFinding`s for each
  failing check.
- The analyzer hooks into the `http_request_activity` response path — after
  the raw response arrives but before the capture re-enters agent context —
  and runs synchronously within the same activity invocation. The analyzer
  reads raw response surfaces (multi-value headers, body artifact) internally
  but all emitted findings are placeholder-redacted (see R6).
- Three analysis dimensions: **JWT structure** (alg=none, missing exp/iat claims,
  embedded key-material quality when present), **cookie attributes** (Secure,
  HttpOnly, SameSite, Path/Domain scope), and **session token quality**
  (predictable patterns, short entropy, Shannon entropy thresholds).
- Findings are fingerprinted deterministically (per `compute_fingerprint`) and flow
  through the existing dedup → report pipeline alongside code-hunted auth candidates.
- The analyzer is **opt-in** — it only runs when an auth profile is present on the
  `HttpRequestSpec` and the response carries candidate tokens/cookies.

## Related specs

- `target-authentication` — auth profile declaration and credential resolution
- `browser-authentication` — browser-based login session capture
- `dynamic-validation-live-http` — guarded live HTTP path
- `dynamic-validation-stage` — pipeline placement of live corroboration
- `hunt-stage` — parallel agent hunt; auth class template already names JWT/cookie issues

Unlocks: t_5ee15309 (authZ matrix).

## Impact

- New vulnerability-class findings (no change to existing AUTH hunt behavior).
- No new dependencies — JWT parsing is a ~100 line pure-Python decoder; token entropy
  uses stdlib only; cookie parsing is stdlib `http.cookies`.
- The analyzer runs in-activity (same worker process, same Temporal task queue), so
  no new infrastructure or network hops.
- Opt-in: a scan without an auth profile triggers no token analysis.

## Scope reconciliation (original ticket 2026-09-10 → current tree b284af7)

Since the ticket was written the codebase absorbed ~45 merges. These items from the
original acceptance criteria are already covered or obsoleted:

- **Bearer/cookie credential injection**: ✅ RESOLVED — `resolve_credentials`
  (`src/quarry_activities/credentials.py:317-461`) handles all 6 `AuthProfileKind`
  variants including `COOKIE` and `LOGIN_FLOW`. No spec change needed.
- **Browser-login session capture**: ✅ RESOLVED — `BrowserLoginResolver`
  (`src/quarry_activities/browser_login.py:79-180`) captures Playwright storage state
  and returns it as a `CachedCredential`. No spec change needed.
- **Live-session context across exploitation turns**: ✅ RESOLVED —
  `LiveSessionContext` (`src/quarry/schemas.py:1463-1475`) carries cookies, tokens, and
  discovered IDs across exploitation turns. No spec change needed.
- **Cookie extraction from login responses (`from_cookie`)**: ❌ DROPPED — The
  `CredentialExtract.from_cookie` field exists but `_extract_from_response` raises
  `NotImplementedError` (`credentials.py:254-255`). The ticket's original scope included
  completing this, but the browser-login path already captures full cookie state for
  JS/SSO targets, and the `COOKIE` profile kind handles static cookies. Cookie
  EXTRACTION from raw Set-Cookie headers (non-browser) is re-assessed here as part of
  the analysis pipeline — the analyzer will parse cookies from the raw multi-value
  response headers (httpx multi-dict) directly rather than completing a separate
  extraction path.
- **JWT-specific AuthProfileKind**: ❌ DROPPED — The original ticket envisioned a
  `JWT` auth profile kind. The current system already handles JWTs through the
  `BEARER` kind (Authorization: Bearer …) and JWT analysis belongs in the analyzer
  (this change) rather than in credential resolution. A JWT is just a bearer
  token — its structure is a concern of analysis, not injection.
- **Session lifecycle tracking (logout, renewal, timeout)**: ❌ DROPPED as a first
  increment. Multi-request session lifecycle analysis requires correlation across
  exploitation-loop turns and is a follow-up capability. This change analyzes single
  tokens/cookies at capture time.
- **TUI live-tail of session analysis**: ❌ DROPPED — Same UX separation as every
  previous lane. Build the analysis artifact first; a TUI screen consuming it is a
  separate change.

## Non-goals

- Not a general-purpose JWT library — only the analysis surface needed for the checklist
  is implemented.
- Not a replacement for the AUTH hunt agent — this is a deterministic supplement that
  catches what the LLM cannot see (real token properties).
- Not a session lifecycle tracker (logout/invalidation/renewal) — single-shot
  token/cookie analysis only in this increment.
- Does not modify `CredentialExtract` or the login_flow resolution path.