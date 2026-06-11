# ADR 018: Target authentication and credential resolution

## Status

Accepted

## Context

ADR-017 defines the opt-in live dynamic path and introduces `HttpRequestSpec.auth_profile` as
a named credential reference, with `Target.auth_config_ref` pointing at "a named credential
from Target.auth_config_ref / environment variables." Neither is defined further: the format of
a credential profile, the env-var naming convention, the set of supported credential types, and
any mechanism for dynamic credential acquisition are entirely absent from the design.

The IDOR demo in week-14-5 says the agent "fetches a second user's object with a legitimate
token" — but nothing explains how that token is supplied, attached to the request, or kept out
of the agent's reasoning chain. The static validator-independence design depends on the agent
never seeing raw secrets; the scrubber strips `Bearer`/`Basic` headers and a `SENSITIVE_ENV_KEYS`
list — but `SENSITIVE_ENV_KEYS` is nowhere defined, and the scrubber cannot strip a token it
has never been told about.

Additionally, many real-world targets gate their API behind a full login flow (POST credentials,
receive a session token or cookie) and some require a TOTP/OTP second factor. Without a way to
acquire and cache those credentials, the live dynamic path cannot reach behind any authentication
boundary, limiting it to unauthenticated or token-pre-issued targets only.

Constraints from the existing design that this ADR must not break:

- **`quarry.toml` is safe to commit.** This boundary (adr-015:33-36) must extend to auth
  profiles: no secret values may appear in any committed file.
- **The agent never sees raw secrets.** The agent proposes `HttpRequestSpec(auth_profile="name")`.
  At no point does the concrete token, password, or OTP enter the agent's context, prompt, or
  any persisted domain object it can inspect.
- **ADR-017's six-layer safety boundary is unchanged.** Auth resolution is additive on top of
  it; it does not relax any layer.
- **Non-deterministic work runs in activities, not workflow code.** TOTP generation and login
  HTTP calls are both non-deterministic and belong on the `quarry-dynamic` task queue (ADR-014).
- **Login POST is non-idempotent.** The ADR-017 rule for POST/PUT/DELETE (non-retryable or
  idempotency-key) applies to login steps.
- **The scrubber must know every concrete secret value used in a scan.** Per-run scrubber
  denylist registration is mandatory so echoed tokens in later response bodies are redacted
  before re-entering any prompt.

## Decision

Add a declarative `AuthProfile` model that separates the *structure* of authentication from the
*values* of secrets. Profiles are loaded from a gitignored `auth-profiles.toml` (pointed to by
`Target.auth_config_ref`). Secret values are never stored in profiles — they are
`SecretRef(env="QUARRY_SECRET_…")` pointers resolved at dispatch time from the process
environment. Credential resolution occurs **only inside the `quarry-dynamic` worker at activity
dispatch time** — never in agent context, workflow code, or the `ToolRunner` orchestrator process.

### 1. Declaration / value separation

An `AuthProfile` declares *how* to authenticate. Secret *values* live exclusively in env vars
(`.env`, not committed) under the `QUARRY_SECRET_*` prefix. `auth-profiles.toml` is a
non-secret structural file; it may be committed if it contains no inline values. If in doubt:
gitignore it. The loader raises `ValueError` at `resolve_auth()` time if any `SecretRef.env`
value is absent from the environment (fail-fast, before any model call, consistent with
`resolve_focus()` and `resolve_dynamic()`).

The prefix convention `QUARRY_SECRET_*` is added to `SENSITIVE_ENV_KEYS` (architecture.md:564),
ensuring every env var under this namespace is stripped by the scrubber even if it is
accidentally echoed in a tool result or log line.

### 2. `AuthProfile` schema

See `docs/schemas.md` for the normative definitions of `SecretRef`, `TotpConfig`,
`CredentialExtract`, `LoginStep`, `AuthProfileKind`, `AuthProfile`, `AuthProfileSet`, and
`CredentialProvider`. The summary shape:

```
AuthProfile
├── name             str                     matches HttpRequestSpec.auth_profile
├── kind             AuthProfileKind         bearer | basic | static_header | cookie | login_flow
├── secret_ref       SecretRef | None        pointer to the env var holding the secret value
├── username         str | None              non-secret username (basic auth / login template)
├── name_hint        str | None              custom header/cookie name
├── login            LoginStep | None        required when kind == login_flow
│   ├── path         str                     login endpoint path (host in allowed_hosts)
│   ├── field_template  dict[str, str]       placeholders: ${secret:ENV}, ${totp}, ${username}
│   ├── extract      CredentialExtract       where to find the token in the login response
│   └── ttl_seconds  int | None              in-memory cache TTL; re-login on expiry or 401
└── totp             TotpConfig | None       TOTP config when the login is OTP-gated
    └── seed_ref     SecretRef               base32 TOTP seed in env
```

No inline secrets at any level. `ToolRunner` rejects any `HttpRequestSpec.auth_profile` whose
value matches a credential pattern (existing rule, adr-017; now extended: it must be a name
that maps to an `AuthProfile`, not a raw token).

### 3. Supported credential kinds

| Kind | How it resolves | Attached as |
|---|---|---|
| `bearer` | `secret_ref` → env var value | `Authorization: Bearer <value>` |
| `basic` | `username` + `secret_ref` (password) | `Authorization: Basic <b64>` |
| `static_header` | `secret_ref` → env var value | `<name_hint>: <value>` (default `X-Api-Key`) |
| `cookie` | `secret_ref` → env var value | `Cookie: <name_hint>=<value>` |
| `login_flow` | Execute `LoginStep`, extract credential | Per `CredentialExtract.inject_as` |

All kinds register the resolved concrete value into the per-run scrubber denylist before any
request is sent.

### 4. Resolution flow (worker-only)

Resolution occurs inside the `quarry-dynamic` activity, after all six ADR-017 safety layers
are verified:

1. Agent proposes `HttpRequestSpec(auth_profile="admin_user", …)`.
2. `ToolRunner` confirms `auth_profile` is a registered name (not a raw token). Records a
   refused `ToolInvocation` with `denied_reason="invalid_auth_profile"` if not recognized.
3. The `quarry-dynamic` activity receives the spec and resolves the named profile from the
   run's `AuthProfileSet`:
   - Static kinds: read `secret_ref.env` from process environment; build header/cookie.
   - `login_flow`: check `CredentialCache`. If cached and not expired and no prior `401`,
     use the cached credential. Otherwise: build the login request, substituting
     `${secret:ENV}` (env lookup), `${username}` (profile field), and `${totp}` (fresh OTP
     from `TotpProvider`); send to `LoginStep.path` (host validated against `allowed_hosts`);
     extract per `CredentialExtract`; store in `CredentialCache(ttl=ttl_seconds)`.
4. Register the concrete credential value in the per-run scrubber denylist via
   `Scrubber.register_secret(value)`. This guarantees the token is redacted from all
   subsequent prompt context.
5. Attach the credential to the outgoing request; send. The agent never sees the attachment.
6. On `401` response from the target: invalidate the `CredentialCache` entry and retry the
   login flow once. If the retry also returns `401`, mark the finding `needs_manual_review`
   and surface an explicit `auth_failed` artifact.

`CredentialCache` is **in-memory, per-run, never persisted**. It is not returned to the agent
or workflow; it is not written to the scan database. It is discarded when the scan process exits.

### 5. TOTP implementation

`TotpProvider` implements `CredentialProvider`:

```python
class TotpProvider:
    def provide(self, profile: AuthProfile, secrets: SecretEnv) -> str:
        seed = secrets.get(profile.totp.seed_ref.env)  # base32 string
        # RFC 6238: HMAC-based OTP, configurable digits/period/algorithm
        return _totp(seed, profile.totp.digits, profile.totp.period_seconds,
                     profile.totp.algorithm)
```

`TotpProvider` generates the OTP fresh on each login step invocation. OTP values are
ephemeral and never cached. The seed (`QUARRY_SECRET_*` env var) is registered in the
scrubber denylist. Because TOTP generation reads the system clock it is non-deterministic
and must run in the `quarry-dynamic` activity, not in workflow code.

The `CredentialProvider` protocol leaves the interface open for SMS/push/hardware-key OTP
without requiring schema changes.

### 6. Prove-sandbox credential injection

The egress-restricted sandbox (`prove`) cannot call back to the `quarry-dynamic` worker at
execution time. The prove activity therefore resolves the credential worker-side first
(reusing the same `CredentialCache` — a single login/TOTP occurs), then injects the
already-resolved concrete credential into the sandbox as a named env var keyed by profile name
(e.g. `QUARRY_INJECTED_CRED_<profile_name>=<value>`). The in-sandbox `http_request` helper
attaches it by profile name; the prove agent only ever sees the profile name. Egress is still
pinned to the authorized target IP, so the blast radius of a compromised sandbox is bounded
to the authorized host.

Injected credential env vars in the sandbox are also added to the per-run scrubber denylist
so any echoed token in the proof response artifact is redacted before it re-enters the prompt
or the final report.

### 7. `resolve_auth()` startup validation

Add `resolve_auth(config: ScanConfig, target: Target) -> AuthProfileSet | None` in
`src/quarry/panel_config.py` alongside `resolve_dynamic()`. When a live flag is on:

1. If `target.auth_config_ref` is `None`: return `None` (unauthenticated scans are valid).
2. Load `auth-profiles.toml` from the path given by `auth_config_ref`.
3. For every `SecretRef.env` referenced in every `AuthProfile`: assert the env var is set in
   the process environment. Raise `ValueError` with a message naming the first missing var.
4. For every `LoginStep.path`: assert the host (resolved from `target.target_url`) is in
   `Target.allowed_hosts`. Raise `ValueError` on any out-of-scope login endpoint.

Call `resolve_auth()` after `resolve_dynamic()` in the CLI scan-start path, before any model
call. If it raises, abort with a clear user-facing error.

### 8. Config and CLI

`Target.auth_config_ref` accepts a path to the `auth-profiles.toml` file. This path may be
relative to the repo root or absolute. If it refers to a file with any `SecretRef.env` value
inline (i.e., a literal token), the loader raises and refuses to start.

No new CLI flags are needed for auth: profile selection is structural (the profile name appears
in the scan input or is the single profile in the file). `resolve_auth()` fails fast on any
misconfiguration before the scan starts.

Add `auth_config_ref` to `quarry.toml.example`'s `[scan.defaults]` block (commented out),
pointing at `auth-profiles.toml.example`. Add a note: "`auth-profiles.toml` is gitignored by
convention; it contains env-ref structure only, never raw secret values."

### 9. Backward compatibility

When `auth_config_ref` is `None` (the default): `resolve_auth()` returns `None`, no
`AuthProfileSet` is loaded, no `CredentialCache` is created, and the live dynamic path
proceeds unauthenticated (exactly today's behavior). No new activity is scheduled, no new
Temporal worker is touched.

A scan with no `auth_config_ref` and `dynamic_validation_enabled=False` produces output
identical to pre-ADR-018: no credential resolution, no scrubber denylist extensions, no
`CredentialCache`. This is a required cut-line test in week-14-6.

## Consequences

### Easier

- Quarry can authenticate to a target using any of the five kinds, covering the majority of
  real-world API authentication mechanisms.
- TOTP/OTP support unblocks testing behind software-2FA-gated login pages.
- The agent never sees raw secrets, preserving the validator-independence and prompt-injection
  properties from ADR-017 and week-13.
- The `CredentialProvider` protocol leaves the door open for future MFA mechanisms without
  a schema change.
- `QUARRY_SECRET_*` prefix + scrubber denylist registration means any accidentally echoed
  token is redacted before it reaches any prompt or log, with no manual scrubber maintenance.
- Startup validation (`resolve_auth()`) surfaces misconfiguration before any model call or
  network activity, consistent with the fail-fast pattern established by `resolve_focus()` and
  `resolve_dynamic()`.

### Harder

- The `quarry-dynamic` worker acquires a new responsibility: credential resolution. This is an
  additional surface that must be tested, especially the `login_flow` path.
- `CredentialCache` lifetime management (TTL + 401-invalidation) adds state to the activity
  worker. Tests must cover cache hit, cache miss, expiry, and 401-invalidation.
- Login `POST` is non-idempotent. The login activity (or the step within the dynamic activity)
  must be non-retryable, consistent with ADR-017's POST/PUT/DELETE rule.
- The prove sandbox injection path adds a new interface point: the prove activity must resolve
  the credential before it creates the sandbox job, and the sandbox `http_request` helper must
  consume the injected env var by profile name.
- Every new `SecretRef.env` reference is a potential startup failure if the env var is absent.
  The `resolve_auth()` validation message must name the missing var clearly.
- Login-response bodies are target-controlled content. The extracted credential must not be
  logged, returned to the agent, or stored in any domain object. Only the scrubber denylist
  entry and the in-memory `CredentialCache` may hold the value.

### Explicitly not doing

- Playwright or browser-based login flows. ADR-017 defers browser automation to 0.3; this ADR
  inherits that deferral. All auth flows in M2 are `httpx`-based.
- Push/SMS/hardware-key OTP. `TotpProvider` is the only M2 `CredentialProvider` implementation.
  The protocol is open; other providers are 0.3 candidates.
- Persisting resolved credentials to the scan database. Tokens are in-memory only.
- OAuth 2.0 / OIDC flows. The `login_flow` kind covers simple credential-exchange flows; full
  OAuth with redirect and PKCE is a 0.3 candidate.
- Credential rotation or multi-credential profiles. Each profile maps to one credential.
- Exposing the concrete token to the agent or report. The agent sees only the profile name;
  the report records `auth_profile_used: str` (the name), never the value.

## Alternatives considered

### Inline credentials in `quarry.toml` or `HttpRequestSpec`

Rejected. `quarry.toml` is designed to be safe to commit (adr-015). Inline credentials in the
request spec would make them visible to the agent, violating the "agent never sees raw secrets"
invariant and potentially leaking into model traces, logs, or persisted domain objects.

### Resolve credentials at the `ToolRunner` boundary (orchestrator process)

Rejected (alternative explicitly declined in planning). The orchestrator process is the widest
blast radius: any resolved token would be in-process with all workflow state, model calls, and
logging. Worker-only resolution contains the secret to the `quarry-dynamic` process, which
already has the most restricted network surface (enforces `allowed_hosts` independently).

### Store resolved credentials in `ToolInvocation` artifacts for traceability

Rejected. `ToolInvocation` rows are persisted domain objects that may appear in reports,
exports, or debugging UIs. Storing concrete tokens there would compromise the "never persisted"
invariant. Traceability is achieved through `auth_profile_used: str` (the name) and
`scrubber_hits` on the response artifact.

### Implement full OAuth 2.0 / OIDC in M2

Rejected for scope reasons. OAuth adds redirect, authorization-code, PKCE, token exchange,
and refresh flows that are disproportionate to M2. The `login_flow` kind covers POST-credential
exchanges (the common case for internal APIs and staging environments). OAuth is a 0.3 candidate.
