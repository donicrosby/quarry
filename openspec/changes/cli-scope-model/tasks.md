## 1. Validate ScopeExclusion kinds at parse time

- [ ] Add a `VALID_SCOPE_EXCLUSION_KINDS` constant in `quarry/schemas.py` listing the
  recognized kinds: `route`, `path_glob`, `functional_area`, `vuln_class`, `command`,
  `binary`, `filesystem_path`, `note` (8 total).
- [ ] Add a Pydantic field validator on `ScopeExclusion.kind` that rejects unknown kinds
  with a message listing valid kinds.
- [ ] Add a unit test in `tests/unit/test_agentic_schemas.py` that
  `ScopeExclusion(kind="made_up", ...)` raises `ValidationError`.
- [ ] Add a unit test confirming all eight valid kinds parse without error.
- [ ] Verify existing tests using `kind="note"` (`tests/unit/test_agentic_schemas.py:44`,
  `tests/unit/test_scope_exclusions.py:43`) still pass — `note` must be in the valid
  kinds set.
- [ ] Run `uv run pytest tests/unit/test_agentic_schemas.py
  tests/unit/test_scope_exclusions.py -q` — all tests pass.

## 2. Implement binary exclusion kind in ToolRunner

- [ ] Add a `kind == "binary"` branch in `_matches_scope_exclusion`
  (`src/quarry_tools/runner.py`) that resolves the command name from
  `inputs.get("command")` via `shutil.which` (bare names) or direct identity (absolute
  paths), then fnmatch-matches the resolved path against the exclusion value.
- [ ] Resolution SHALL occur within `_matches_scope_exclusion` itself — no separate
  `resolved_binary` key from downstream needed.
- [ ] When `shutil.which` cannot resolve a bare command name and it is not an absolute
  path, the exclusion SHALL NOT match (fail-open for missing resolution data).
- [ ] Add unit tests in `tests/unit/test_runner_sandbox_scope_guard.py`:
  - `test_binary_exclusion_refuses_resolved_path` — `command="curl"` resolved to
    `/usr/bin/curl` blocked by `value="/usr/bin/curl"`
  - `test_binary_exclusion_allows_different_resolved_path` — `/usr/local/bin/curl`
    allowed when only `/usr/bin/curl` is excluded
  - `test_binary_exclusion_fail_open_unresolvable` — unresolvable bare name does not
    trigger the exclusion (fail-open)
  - `test_binary_exclusion_without_block_dynamic_does_not_refuse` —
    `block_dynamic=False` passes through
- [ ] Run `uv run pytest tests/unit/test_runner_sandbox_scope_guard.py -q` — all tests pass.

## 3. Implement filesystem_path exclusion kind in ToolRunner

- [ ] Add a `kind == "filesystem_path"` branch in `_matches_scope_exclusion`
  (`src/quarry_tools/runner.py`) that matches `input_files` keys (for `run_in_sandbox`;
  that tool has no `path` input) against the exclusion value using fnmatch.
- [ ] Add a separate `filesystem_path` pre-check at the static-path branch in
  `ToolRunner.run()` (`src/quarry_tools/runner.py:319`), BEFORE the existing
  `_resolve_path` escape check. This check SHALL iterate over
  `self._scope_exclusions` for `kind == "filesystem_path"` and return a refused
  `ToolCallRecord` on match. This preserves the invariant that static tools are
  unaffected by sandbox-scoped exclusions (`command`, `binary`).
- [ ] Add unit tests in `tests/unit/test_tool_runner_guard.py`:
  - `test_filesystem_path_exclusion_blocks_read_file` — `read_file` to `.git/config`
    refused when `filesystem_path` value is `.git/**`
  - `test_filesystem_path_exclusion_blocks_sandbox_input_files` — `run_in_sandbox` with
    `input_files` key matching a `filesystem_path` exclusion is refused
  - `test_filesystem_path_exclusion_allows_unrelated_paths` — unrelated paths are not
    blocked
  - `test_filesystem_path_exclusion_absolute_path_blocked` — an absolute path matching
    the exclusion is blocked regardless of cwd
- [ ] Add an invariant-preservation test in
  `tests/unit/test_runner_sandbox_scope_guard.py`:
  - `test_command_exclusion_does_not_affect_static_tools` — a `kind="command"` exclusion
    does NOT block `read_file` (this test already exists at line 215; verify it still
    passes).
- [ ] Run `uv run pytest tests/unit/test_tool_runner_guard.py -q` — all tests pass.

## 4. Add tiered sandbox confinement guard

- [ ] In `sandbox.py`, add or clarify the module-level docstring to document the tiered
  confinement model: Tier 1 (`LocalSubprocessSandbox`) provides resource containment
  plus defense-in-depth via the command allowlist and workdir restriction, but shares
  the host kernel, filesystem, and network stack. Tier 2+ (`ContainerSandbox`,
  `K8sJobSandbox`) provides kernel-enforced isolation.
- [ ] Ensure the existing workdir restriction (`_resolve_sandbox_cwd`,
  `_stage_input_files`) correctly rejects host paths outside the sandbox workdir for
  Tier 1 — these guards are defense-in-depth, not a kernel-enforced guarantee.
- [ ] Add a unit test verifying that a sandbox execution spec with a `cwd` pointing
  outside the workdir raises `ToolSecurityError` (if not already covered).
- [ ] Run `uv run pytest tests/integration/test_local_sandbox.py
  tests/unit/test_runner_sandbox_scope_guard.py -q` — all tests pass.

## 5. Validate the change end-to-end

- [ ] Run `npx openspec validate cli-scope-model --strict` — clean output.
- [ ] Verify all parent citations: the spec references concrete code symbols in
  backticks, all source-file paths exist, all test-file paths exist.
- [ ] Run the full gate suite: `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run pyright`, `uv run pytest tests/unit -q -n 4`.
- [ ] Commit on branch `spec/cli-scope-model` with message
  `spec: enforce cli-scope-model scope exclusions and tiered sandbox confinement`
  (unique on the branch — must not duplicate the planner's landed spec-commit subjects).
- [ ] Try `gh auth setup-git` and push; park locally on failure and report the
  implementation commit SHA in run metadata.
