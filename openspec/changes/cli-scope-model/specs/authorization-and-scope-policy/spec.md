## ADDED Requirements

### Requirement: Binary exclusion kind blocks sandbox execution by resolved path

The scope exclusion system SHALL support a `binary` kind that blocks `run_in_sandbox`
invocations by the resolved binary path. Resolution SHALL occur within
`_matches_scope_exclusion` (`src/quarry_tools/runner.py`) via `shutil.which` for bare
command names or direct identity for absolute paths — NOT downstream in
`sandbox_exec_activity`. This is distinct from the `command` kind which matches the
agent-supplied command name before resolution.

#### Scenario: binary-exclusion-blocks-resolved-binary-path

- **WHEN** a `run_in_sandbox` invocation carries `command="curl"` and `shutil.which` resolves
  it to `/usr/bin/curl`, and a scope exclusion with `kind="binary"` and
  `value="/usr/bin/curl"` is active
- **THEN** the invocation is refused with a denial reason naming the binary path

#### Scenario: binary-exclusion-allows-different-binary-same-name

- **WHEN** a `run_in_sandbox` invocation resolves to `/usr/local/bin/curl` and a scope
  exclusion blocks only `/usr/bin/curl`
- **THEN** the invocation is allowed (match is against the resolved path, not the basename)

#### Scenario: binary-exclusion-fail-open-when-unresolvable

- **WHEN** a `run_in_sandbox` invocation carries a `command` that `shutil.which` cannot
  resolve and is not an absolute path
- **THEN** the `binary` exclusion SHALL NOT match (fail-open for missing resolution data)

#### Scenario: binary-exclusion-ignored-when-block-dynamic-false

- **WHEN** a `binary` scope exclusion has `block_dynamic=False`
- **THEN** `_matches_scope_exclusion` returns `False` regardless of the binary path

### Requirement: Filesystem path exclusion blocks tool access to sensitive paths

The scope exclusion system SHALL support a `filesystem_path` kind that blocks access to
paths matching the exclusion value. For static tools the check SHALL be applied at the
static-path branch in `ToolRunner.run()` (`src/quarry_tools/runner.py:319`); for
`run_in_sandbox` it uses the existing `_check_scope_exclusion` path. This design
preserves the invariant that static tools are unaffected by sandbox-scoped exclusions
(`command`, `binary`).

#### Scenario: filesystem-path-exclusion-blocks-git-directory-access

- **WHEN** a scope exclusion has `kind="filesystem_path"` and `value=".git/**"` and a tool
  attempts to read `.git/config`
- **THEN** the tool invocation is refused

#### Scenario: filesystem-path-exclusion-allows-unrelated-paths

- **WHEN** a scope exclusion blocks `.git/**` and a tool reads `src/main.py`
- **THEN** the read is allowed

#### Scenario: filesystem-path-exclusion-preserves-static-tool-invariant

- **WHEN** a scope exclusion has `kind="command"` (a sandbox-scoped kind) and a static tool
  such as `read_file` is invoked
- **THEN** the invocation is NOT blocked by the `command` exclusion (the existing
  `_check_scope_exclusion` gate runs only for `_DYNAMIC_TOOLS`)

### Requirement: Sandbox execution confinement tiers

Sandbox execution confinement SHALL be tiered. Tier 1 (`LocalSubprocessSandbox`) provides
resource containment plus defense-in-depth via the command allowlist and workdir
restriction, but shares the host kernel, filesystem, and network stack. Tier 2+
(`ContainerSandbox`, `K8sJobSandbox`) provides kernel-enforced isolation where the host
is not a reachable target. Privilege-escalation checks SHALL execute inside the sandbox
regardless of tier.

#### Scenario: tier1-confinement-via-allowlist-and-workdir

- **WHEN** a `LocalSubprocessSandbox` executes a command
- **THEN** the command SHALL be validated against `_COMMAND_ALLOWLIST` and the working
  directory SHALL be restricted to the sandbox workdir; host paths outside the workdir
  are rejected

#### Scenario: tier2-confinement-hides-host

- **WHEN** a `ContainerSandbox` or `K8sJobSandbox` executes a command
- **THEN** the execution is kernel-enforced confined to the sandbox; host processes,
  filesystem, and network interfaces are not accessible as targets

#### Scenario: privilege-escalation-checks-operate-inside-sandbox-only

- **WHEN** a privilege escalation check runs
- **THEN** it attempts escalation only within the sandbox, never against the host kernel or
  host processes

### Requirement: Unknown scope exclusion kinds are rejected at parse time

Scan profile parsing SHALL reject unknown scope exclusion kinds at load time. An unknown
kind SHALL cause profile validation to fail with an error message listing the valid kinds:
`route`, `path_glob`, `functional_area`, `vuln_class`, `command`, `binary`,
`filesystem_path`, and `note` (8 total). The existing `kind="note"` exclusions used in
test fixtures and prompt blocks SHALL continue to parse without error.

#### Scenario: unknown-kind-causes-parse-failure

- **WHEN** a scan profile contains a scope exclusion with `kind="made_up_kind"`
- **THEN** profile validation fails with an error listing valid kinds

#### Scenario: valid-kinds-parse-successfully

- **WHEN** a scan profile contains only recognized kinds (`route`, `path_glob`,
  `functional_area`, `vuln_class`, `command`, `binary`, `filesystem_path`, `note`)
- **THEN** profile validation succeeds
