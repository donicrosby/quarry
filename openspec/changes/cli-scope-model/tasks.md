## 1. Validate ScopeExclusion kinds at parse time

- [ ] Add a `VALID_SCOPE_EXCLUSION_KINDS` constant in `quarry/schemas.py` listing the
  recognized kinds: `route`, `path_glob`, `functional_area`, `vuln_class`, `command`,
  `binary`, `filesystem_path`.
- [ ] Add a Pydantic field validator on `ScopeExclusion.kind` that rejects unknown kinds
  with a message listing valid kinds.
- [ ] Add a unit test in `tests/unit/test_agentic_schemas.py` that
  `ScopeExclusion(kind="made_up", ...)` raises `ValidationError`.
- [ ] Add a unit test confirming all seven valid kinds parse without error.
- [ ] Run `pytest tests/unit/test_agentic_schemas.py -q` — all tests pass.

## 2. Implement binary exclusion kind in ToolRunner

- [ ] Add a `kind == "binary"` branch in `_matches_scope_exclusion` (`src/quarry_tools/runner.py`)
  that extracts the resolved binary path from inputs and fnmatch-matches it against the
  exclusion value.
- [ ] The `binary` kind SHALL be matched against the resolved path (post-shutil.which or
  absolute), not the agent-supplied command name. When the resolved path is not available
  in tool inputs, the exclusion SHALL NOT match (fail-open for missing data).
- [ ] Add unit tests in `tests/unit/test_runner_sandbox_scope_guard.py`:
  - `test_binary_exclusion_refuses_resolved_path` — resolved `/usr/bin/curl` blocked by
    `value="/usr/bin/curl"`
  - `test_binary_exclusion_allows_different_resolved_path` — `/usr/local/bin/curl` allowed
    when only `/usr/bin/curl` is excluded
  - `test_binary_exclusion_without_block_dynamic_does_not_refuse` — `block_dynamic=False`
    passes through
- [ ] Run `pytest tests/unit/test_runner_sandbox_scope_guard.py -q` — all tests pass.

## 3. Implement filesystem_path exclusion kind in ToolRunner

- [ ] Add a `kind == "filesystem_path"` branch in `_matches_scope_exclusion`
  (`src/quarry_tools/runner.py`) that matches the `path` input field (for `read_file`,
  `grep`, `scip_index`) and `input_files` keys (for `run_in_sandbox`) against the
  exclusion value using fnmatch.
- [ ] `filesystem_path` SHALL apply independently of the existing `_resolve_path`
  repo-root escape check — it blocks paths even when they are within the repo root.
- [ ] Add unit tests in `tests/unit/test_tool_runner_guard.py`:
  - `test_filesystem_path_exclusion_blocks_read_file` — `read_file` to `.git/config`
    refused when `filesystem_path` value is `.git/**`
  - `test_filesystem_path_exclusion_blocks_sandbox_input_files` — `run_in_sandbox` with
    `input_files` key matching a `filesystem_path` exclusion is refused
  - `test_filesystem_path_exclusion_allows_unrelated_paths` — unrelated paths are not
    blocked
- [ ] Run `pytest tests/unit/test_tool_runner_guard.py -q` — all tests pass.

## 4. Wire binary resolution into sandbox scope check

- [ ] In `sandbox_exec_activity` (`src/quarry_activities/sandbox.py`), resolve the binary
  path (via `shutil.which` for bare names, or direct for absolute paths) BEFORE passing to
  ToolRunner, and include the resolved path in inputs under a `resolved_binary` key.
- [ ] The `binary` exclusion kind in `_matches_scope_exclusion` reads `inputs.get("resolved_binary", "")`.
- [ ] Add an integration test verifying that a `kind="binary"` scope exclusion on
  `/usr/bin/rm` blocks a `run_in_sandbox` invocation with `command="rm"`.
- [ ] Run `pytest tests/ -q -k "sandbox"` — affected sandbox tests pass.

## 5. Add host-is-never-in-scope guard to sandbox execution

- [ ] In `LocalSubprocessSandbox.run()` and `ContainerSandbox.run()`, add an assertion or
  early-return guard that the execution target is within the sandbox working directory, not
  a host path.
- [ ] Document the host-is-never-in-scope policy in a module-level docstring in
  `sandbox.py`: "The sandbox host is NEVER a valid target. All execution is confined to
  the sandbox working directory."
- [ ] Add a unit test verifying that a sandbox execution spec targeting a host path
  (e.g. `/etc/passwd`) raises `ToolSecurityError`.
- [ ] Run `pytest tests/unit/test_runner_sandbox_scope_guard.py -q` — all tests pass.

## 6. Validate the change end-to-end

- [ ] Run `npx openspec validate cli-scope-model --strict` — clean output.
- [ ] Run the full gate suite: `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run pyright`, `uv run pytest tests/unit -q -n 4`.
- [ ] Commit with message `spec: add cli-scope-model change` on branch
  `spec/cli-scope-model`.
- [ ] Try `gh auth setup-git` and push; park locally on failure and report branch SHA.