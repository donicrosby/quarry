# Proposal: cli-scope-model

## Why

The current scope model (`ScopeExclusion`) supports `route`, `path_glob`, `functional_area`,
`vuln_class`, and `command` kinds. During CLI and system testing (notably sandbox-driven
prove/exploit phases and static tool invocations), operators need two additional exclusion
kinds: blocking by resolved binary path (distinct from the agent-supplied command name) and
blocking filesystem access to sensitive paths even when those paths lie within the repo root.

The sandbox host machine is currently not addressed in any scope policy — a gap that leaves
the "is the host in scope for privilege escalation testing?" question unanswered. Closing
that gap codifies a clear, auditable decision.

## What Changes

- **ADD** `binary` exclusion kind: matches against the resolved binary path (post-PATH
  resolution) in `run_in_sandbox`, blocking execution even when the command name is allowed.
- **ADD** `filesystem_path` exclusion kind: blocks static tool access (`read_file`, `grep`,
  `scip_index`, `run_in_sandbox` `input_files` paths) to paths matching the exclusion
  value, independently of the repo-root escape check.
- **ADD** host-is-never-in-scope policy: the sandbox host SHALL NOT be treated as a
  reachable target; all privilege-escalation checks execute exclusively inside the sandbox
  environment.
- **ADD** CLI configurability: the `ScanProfile` `scope_exclusions` list accepts the new
  kinds; validation rejects unknown kinds at profile parse time.

## Non-goals

- Changing the `_COMMAND_ALLOWLIST` (hardcoded sandbox allowlist in `sandbox.py`).
- Modifying `request_in_scope` in `roe.py` — that function deals with live-target HTTP
  scope and is unrelated to CLI/system-test scope.
- Implementing privilege escalation checks — this is the spec for the scope model; the
  priv-esc checks themselves are specced separately.

## Impact

- **Specs**: `authorization-and-scope-policy` (ADDED requirements for new exclusion kinds
  and host-scope decision).
- **Code touched** (for coder reference): `quarry_tools/runner.py` (new kind matchers in
  `_matches_scope_exclusion`), `quarry_activities/sandbox.py` (binary-path resolution in
  scope check), `quarry/schemas.py` (kind validation), `quarry_cli/` (profile parsing).
- **No breaking changes**: new kinds are additive; unknown kinds are rejected at parse time
  (safe fail-closed).

## Reconciled against current tree (main @ b284af7)

The original ticket (2026-09-10) requested three new kinds: `command`, `binary`, and
`filesystem_path`. `command` was already implemented before the ticket was written (commit
5b716db9, 2026-06-12: `_matches_scope_exclusion` `kind == "command"` branch, plus tests in
`test_runner_sandbox_scope_guard.py`). This change drops `command` from scope and adds only
`binary` and `filesystem_path`, plus the host-scope decision that was always implied but
never codified.

**Dropped from original ticket:**
- `command` kind — already shipped (5b716db9, `src/quarry_tools/runner.py:152-156`).
- `request_in_scope` updates — the function in `src/quarry_workflows/roe.py:33` is
  exclusively for live-target HTTP host/path scope; CLI scope exclusions are enforced by
  `ToolRunner._check_scope_exclusion` (`src/quarry_tools/runner.py:190-203`), not
  `request_in_scope`.