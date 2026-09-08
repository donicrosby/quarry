# Responsible use and threat model — live exploitation

Quarry's live-exploitation track (the app-centric "Shannon pillar") does more than read
code: it sends real requests to a running target and chains them to *prove* a
vulnerability by exploiting it. That is a powerful, dual-use capability. This document
states the rules of engagement it enforces, the threat model it assumes, and the
non-negotiable boundaries. It complements the six-layer safety model in
[ADR-017](decisions/adr-017-live-dynamic-validation.md) and the browser-login controls in
[ADR-023](decisions/adr-023-browser-login-dynamic-validation.md).

## Only against systems you are authorized to test

The live-exploitation track is **off by default** and **fail-closed**. It runs only when
*all* of the following are true; if any is missing it is a silent no-op that opens no
socket:

- A CLI flag explicitly opts in (`live_exploit_enabled`). The presence of a target URL
  alone never enables it.
- A live target URL is resolved.
- An **active `TargetAuthorization`** is supplied, naming who authorized the engagement
  (`authorized_by`) and, when set, an expiry (`expires_at`). An expired or unsigned
  authorization is treated as no authorization.

Never point the live-exploitation track at a system you do not own or have explicit,
written permission to test. Unauthorized exploitation of a system you do not control is
likely a crime in most jurisdictions regardless of intent.

## Never against production

Live exploitation is for pre-production and dedicated test environments only. Confirming a
vulnerability by doing means sending crafted requests that can read data, cross tenant
boundaries, or change state. Run it against staging, ephemeral, or purpose-built
vulnerable environments — never against a production system serving real users or holding
real data.

## Rules of engagement are enforced in code, not by convention

The `TargetAuthorization` fields are load-bearing controls, checked before any egress:

- **`allowed_hosts` is fail-closed.** An empty allow-list blocks all traffic. Every
  proposed request's resolved host must be in the allow-list or it is refused before a
  socket is opened. This is enforced independently at the workflow *and* the
  `http-request` activity boundary (defence in depth).
- **`do_not_test` is a hard exclusion.** Any proposed request whose path matches a
  do-not-test glob is refused and recorded with `dispatched=false` — it is never sent.
- **`allowed_repo_paths`** scopes which parts of the codebase the engagement covers.

A request refused by the rules of engagement is recorded as evidence of the refusal, not
dispatched. The agent cannot work around these checks: it only *proposes* requests; the
workflow performs the single, allow-listed egress (propose→dispatch).

## Prove by doing — and keep the proof honest

A live finding becomes a candidate only when a confirmed exploit chain demonstrates it
(`ExploitChain.proven`). Confirmation is evaluated **in code** from the observed response
(e.g. a `status_ok` check), never on the model's unverified say-so. The ordered
request/response chain travels with the finding as its proof, and every step is
provenance-tracked: each agent turn records a model invocation and each dispatched request
records request and response artifacts. A finding with no verifiable chain is not emitted.

## Minimize blast radius

- Prefer read-only and reversible steps. Build the shortest chain that demonstrates the
  flaw; do not exfiltrate data or mutate state beyond what the proof requires.
- Mutating steps require the authorization to permit them; read-mostly is the default
  bias.
- Sessions are captured and chained as **credentials**: they are scrubbed, referenced by
  profile name, and never persisted or surfaced to the agent in raw form. Secrets flow
  only through the credential path; the redaction layer stays on at all times.

## Threat model assumptions

- The target is an authorized, non-production environment reachable only via the
  configured allow-list.
- Responses from the live target are **untrusted input**. They are scrubbed before
  re-entering any prompt and are treated as evidence to analyze, never as instructions to
  follow (prompt-injection containment).
- Credentials and captured sessions are secrets. A leak into an artifact or prompt is a
  defect; the scrubber registers every secret, TOTP code, and session cookie before use.
- Operators are trusted to supply a truthful authorization; the tooling enforces the
  scope that authorization declares but cannot verify the authorization itself is
  legitimate. That responsibility rests with the operator.
