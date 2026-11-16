# Proposal: cli-scope-model

## Why

The current scope model (`ScopeExclusion`) supports `route`, `path_glob`, `functional_area`,
`vuln_class`, and `command` kinds. During CLI and system testing (notably sandbox-driven
prove/exploit phases and static tool invocations), operators need two additional exclusion
kinds: blocking by resolved binary path (distinct from the agent-supplied command name) and
blocking filesystem access to sensitive paths even when those paths lie within the repo root.

The sandbox host machine is currently not addressed in any scope policy — a gap that leaves
the "is the host in scope for privilege escalation testing?" question unanswered. Closing
that gap codifies a tiered, auditable decision.

## What Changes

- **ADD** `binary` exclusion kind: resolves the command name via `shutil.which()` within
  `_matches_scope_exclusion` (`src/quarry_tools/runner.py`) at the ToolRunner pre-gate —
  NOT downstream in `sandbox_exec_activity`. Blocks `run_in_sandbox` execution by the
  resolved binary path even when the command name is allowed. Fail-open when the binary
  cannot be resolved.
- **ADD** `filesystem_path` exclusion kind: for static tools (`read_file`, `grep`,
  `scip_index`), the check is applied at the static-path branch in `ToolRunner.run()`
  (`src/quarry_tools/runner.py:319`) before the `_resolve_path` escape check, preserving
  the invariant that static tools are unaffected by sandbox-scoped exclusions. For
  `run_in_sandbox`, the existing `_check_scope_exclusion` path applies.
- **ADD** tiered sandbox confinement policy: Tier 1 (`LocalSubprocessSandbox`) provides
  resource containment plus defense-in-depth via the command allowlist and workdir
  restriction, but shares the host kernel, filesystem, and network stack. Tier 2+
  (`ContainerSandbox`, `K8sJobSandbox`) provides kernel-enforced isolation where the host
  is not a reachable target. All privilege-escalation checks execute inside the sandbox
  regardless of tier.
- **ADD** CLI configurability: the `ScanProfile` `scope_exclusions` list accepts the new
  kinds; validation rejects unknown kinds at profile parse time. Valid kinds: `route`,
  `path_glob`, `functional_area`, `vuln_class`, `command`, `binary`, `filesystem_path`,
  and `note` (8 total). The existing `kind="note"` usage in tests and prompt blocks
  continues to parse without error.

## Non-goals

- Changing the `_COMMAND_ALLOWLIST` (hardcoded sandbox allowlist in `sandbox.py`).
- Modifying `request_in_scope` in `roe.py` — that function deals with live-target HTTP
  scope and is unrelated to CLI/system-test scope.
- Implementing privilege escalation checks — this is the spec for the scope model; the
  priv-esc checks themselves are specced separately.

## Impact

- **Specs**: `authorization-and-scope-policy` (ADDED requirements for new exclusion kinds,
  tiered host confinement, and valid-kind enumeration).
- **Code touched** (for coder reference): `quarry_tools/runner.py` (new kind matchers in
  `_matches_scope_exclusion`, `filesystem_path` pre-check at static-path branch),
  `quarry/schemas.py` (kind validation, 8 valid kinds including `note`), `quarry_cli/`
  (profile parsing).
- **No breaking changes**: new kinds are additive; unknown kinds are rejected at parse time
  (safe fail-closed); existing `kind="note"` usage is preserved.

## Reconciled against current tree (main @ b284af7)

The original ticket (2026-09-10) requested three new kinds: `command`, `binary`, and
`filesystem_path`. `command` was already implemented before the ticket was written (commit
5b716db9, 2026-06-12: `_matches_scope_exclusion` `kind == "command"` branch, plus tests in
`test_runner_sandbox_scope_guard.py`). This change drops `command` from scope and adds only
`binary` and `filesystem_path`, plus the tiered host-confinement decision that was always
implied but never codified.

**Dropped from original ticket:**
- `command` kind — already shipped (5b716db9, `src/quarry_tools/runner.py:152-156`).
- `request_in_scope` updates — the function in `src/quarry_workflows/roe.py:33` is
  exclusively for live-target HTTP host/path scope; CLI scope exclusions are enforced by
  `ToolRunner._check_scope_exclusion` (`src/quarry_tools/runner.py:190-203`), not
  `request_in_scope`.
