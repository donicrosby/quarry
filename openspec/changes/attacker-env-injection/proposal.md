# Proposal: attacker-env-injection

## Why

An attacker controlling target content (repository files, HTTP responses, tool output) could
use prompt injection to induce the prove agent into specifying sandbox commands that set or
leak environment variables. While the sandbox subsystem already enforces several hard
defenses (empty base env, proxy-var blocking, credential scrubber, command allowlist,
schema-level additionalProperties gate), three gaps persist:

1. **env_profile resolution is a stub.** `EnvProfile.REPO_READONLY` is accepted and validated
   but never resolves to any environment variables — it is dead code today, but a future
   implementation that resolves it could introduce an attacker-controlled injection surface
   if the resolution map includes agent-controllable keys or values.

2. **Shell env-setting in args is not filtered.** `sh` is on the command allowlist, so a
   prompt-injected model could emit `sh -c "VAR=malicious command"` and set arbitrary
   environment variables inside the sandbox process.

3. **`env` on the allowlist leaks non-credential environment.** The `env` command dumps
   every environment variable to stdout. While credential values are scrubbed, non-credential
   vars (PATH, HOME, sandbox paths) leak into the evidence stream and could inform escape
   attempts.

## What Changes

Add four requirements to `proof-and-sandbox-execution`:

- **Agent-controlled env blocked at schema layer** — codifies the existing defense that
  no field on the sandbox tool schema admits arbitrary env vars (already enforced via
  `additionalProperties: False`; made explicit as a spec requirement).

- **env_profile resolution is fail-safe** — the resolution step (when implemented) SHALL
  produce only a fixed mapped set with no agent-controlled keys or values; until
  implemented, the RE PO_READONLY value SHALL be rejected at the tool-call boundary.

- **Shell env-setting args are rejected** — args containing `=` in a leading position or
  paired with env-setting flags SHALL be refused before execution.

- **env command output is restricted** — when `env` is on the allowlist, the sandbox
  SHALL post-filter its output to redact non-credential environment variables before
  returning the capture to the prompt stream.

## Impact

- **Specs touched:** `proof-and-sandbox-execution` (4 ADDED requirements, 8 scenarios)
- **Code touched:** `src/quarry_activities/sandbox.py` (arg validation, env output filter),
  `src/quarry_tools/sandbox_tool.py` (env_profile gate), `src/quarry/schemas.py`
  (EnvProfile enum may narrow)
- **Tests touched:** new unit tests for arg rejection, env output filtering; extended
  sandbox integration tests
- **No breaking changes** to existing workflows or APIs
- **Does not touch** `prompt-injection-defense` directly (env-injection defenses are
  sandbox-layer, not prompt-envelope-layer)

## Non-goals

- Removing `sh` from the command allowlist (needed for legitimate prove scenarios)
- Filtering stdin for env-setting patterns (stdin is attacker-controlled content by design;
  the defense is at the arg and env-profile layers)
- Defending against env-setting via `input_files` content (same rationale — `input_files`
  content is attacker-supplied; the defense is that the sandbox env is built before any
  file is staged and nothing sources input_files automatically)

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
  top-level keys. Codified in REQ-ENV-1 scenario but not a new defense.
- **Pydantic enum validation** — `EnvProfile` enum already enforces only known values at
  the Pydantic boundary (schemas.py:1517-1525). Dropped.
- **auth_profile guard** — `ToolRunner._check_auth_profile` already rejects fabricated
  profile names (runner.py:227-245). Dropped.

What remains from the original intent and is **new in this change**: env-profile resolution
hardening, shell-arg filtering, and env-output restriction.