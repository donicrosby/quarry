# Proposal: attacker-env-injection

## Why

An attacker controlling target content (repository files, HTTP responses, tool output) could
use prompt injection to induce the prove agent into specifying sandbox commands that set or
leak environment variables. While the sandbox subsystem already enforces several hard
defenses (empty base env, proxy-var blocking, credential scrubber, command allowlist,
schema-level additionalProperties gate), three gaps persist:

1. **No controlled env-variable mechanism.** The prove agent has no way to set even
   legitimate, infrastructure-scoped environment variables (PATH, EDITOR, HOME) for
   target-subprocess execution. The gated ticket (t_f92a6a98) calls for a controlled
   `env: dict[str,str]` with allowlist policy — a capability that is currently absent
   and that adversarial validation scenarios depend on.

2. **env_profile resolution is a stub.** `EnvProfile.REPO_READONLY` is accepted and validated
   but never resolves to any environment variables — it is dead code today, but a future
   implementation that resolves it could introduce an attacker-controlled injection surface
   if the resolution map includes agent-controllable keys or values.

3. **Environment-dump output leaks non-credential variables.** Commands that dump the
   process environment (`env`, `printenv`, `python3 -c "import os; print(dict(os.environ))"`)
   leak non-credential variable names and values into the evidence stream. While credential
   values are scrubbed, non-credential vars (PATH, HOME, sandbox paths, and
   QUARRY_INJECTED_CRED_* variable names) leak and could inform escape attempts.

## What Changes

Add four requirements to `proof-and-sandbox-execution`:

- **Controlled env-dict with allowlisted names** — `SandboxExecSpec` gains an `env` field
  restricted to allowlisted variable names with infrastructure-provided (non-agent) values,
  applied to the target subprocess only. This is a controlled capability, not an open
  injection surface.

- **env_profile resolution is fail-safe** — the resolution step (when implemented) SHALL
  produce only a fixed mapped set with no agent-controlled keys or values; until
  implemented, the REPO_READONLY value SHALL be rejected at the tool-call boundary.

- **Arg-level env-setting is defense-in-depth** — leading args matching a `NAME=VALUE`
  prefix (including the `env NAME=VALUE command` idiom) SHALL be rejected; non-leading
  args and `-e`/`--env` SHALL NOT be. This is defense-in-depth only: shell `-c` payloads
  and inline code can set environment at runtime, and the actual protection is the empty
  base environment plus credential scrubbing plus egress gating.

- **Content-keyed env-dump redaction** — any command whose stdout matches an
  environment-dump shape (predominantly KEY=VALUE lines) SHALL have its output redacted
  to a variable-count line before returning to the prompt stream, regardless of which
  allowlisted command produced it.

## Impact

- **Specs touched:** `proof-and-sandbox-execution` (4 ADDED requirements, 14 scenarios)
- **Code touched:** `src/quarry/schemas.py` (SandboxExecSpec gains `env` field with
  allowlist validation), `src/quarry_activities/sandbox.py` (arg validation, env-dump
  output filter, env forwarding to subprocess), `src/quarry_tools/sandbox_tool.py`
  (env_profile gate, tool schema gains `env` property)
- **Tests touched:** new unit tests for env-dict allowlist, arg rejection, content-keyed
  env-dump redaction; extended sandbox integration tests; updated conformance tests
- **No breaking changes** to existing workflows or APIs (env field is additive,
  env_profile gate is a new refusal on a currently-passthrough value)
- **Does not touch** `prompt-injection-defense` directly (env-injection defenses are
  sandbox-layer, not prompt-envelope-layer)

## Non-goals

- Removing `sh`, `env`, `python3`, or `uv` from the command allowlist (needed for
  legitimate prove scenarios)
- Filtering stdin or `input_files` for env-setting patterns (both are attacker-controlled
  content by design; the defense is that the sandbox env is built before any file is
  staged and nothing sources input_files automatically)
- Agent-chosen env variable **values** — the `env` dict restricts values to a fixed
  set of infrastructure-provided strings; the agent may only select from allowed values
  for each allowlisted name
- Preventing env mutation at runtime by shell `-c` payloads or inline code — any code
  running inside the sandbox can set its own environment; the actual protection is the
  empty base environment plus credential scrubbing plus egress gating
- Obfuscated or transformed environment dumps (Python dict reprs such as
  `print(dict(os.environ))`, base64/hex encodings) — the shape detector matches
  plaintext `KEY=VALUE` dumps only; credential values in any form remain covered by
  the pre-existing scrubber

## Reconciled from 2026-09-10 ticket (t_f92a6a98)

The original ticket predates ~45 merges. Defenses that **already exist and therefore dropped
from this change**:

- **Empty base environment** — `_build_safe_env` already starts from `{}` (sandbox.py:204).
  This change does not re-spec it.
- **Proxy-var blocking** — `BLOCKED_ENV_PREFIXES` already covers HTTP_PROXY / HTTPS_PROXY /
  ALL_PROXY / NO_PROXY / FTP_PROXY (sandbox.py:117-128). Dropped from this change.
- **Worker-side credential resolution** — `_resolve_credentials` already runs in the
  activity worker, not the agent context (sandbox_exec.py:77-124). Dropped.
- **Credential scrubber** — `build_scrubber_with_creds` already pre-registers all
  credential values (sandbox_exec.py:63-75). Dropped.
- **Schema additionalProperties gate** — `sandbox_tool.py:82` already blocks unknown
  top-level keys. Dropped from this change (the new `env` field is an explicit property,
  not a gap in the gate).
- **Pydantic enum validation** — `EnvProfile` enum already enforces only known values at
  the Pydantic boundary (schemas.py:1524-1525). Dropped.
- **auth_profile guard** — `ToolRunner._check_auth_profile` already rejects fabricated
  profile names (runner.py:227-245). Dropped.

**Dropped capability (t_f92a6a98 Scope 1):** The ticket's Scope 1 calls for a general
`env: dict[str,str]` on SandboxExecSpec with agent-chosen values. This change re-scopes
that to a **controlled** env-dict: names are allowlisted, values are restricted to
infrastructure-provided strings (not arbitrary agent input), and the env is applied to
the target subprocess only. This controlled capability satisfies the ticket's Acceptance
(EDITOR=/bin/sh proof on vulnerable-cli) while preserving the containment properties the
existing defenses enforce.

**Dropped capability (t_f92a6a98 Scope 3):** the ticket's Scope 3 proofs — LD_PRELOAD
pointing at a malicious `.so`, and PATH set to `/tmp` for hijack — are likewise dropped:
`LD_PRELOAD` is not on the name allowlist and `/tmp`-style PATH values are not on the
value allowlist (see the REQ-1 rejection scenarios). The covered proof path is the
Acceptance's `EDITOR=/bin/sh` on vulnerable-cli via the controlled env-dict. The ticket
owner should strike or defer Scope 3 accordingly.

What remains from the original intent and is **new in this change**: controlled env-dict
with allowlisted names, env-profile resolution hardening (fail-safe), arg-level
defense-in-depth filtering, and content-keyed env-dump redaction.