## ADDED Requirements

### Requirement: Binary exclusion kind blocks sandbox execution by resolved path

The scope exclusion system SHALL support a `binary` kind that blocks `run_in_sandbox`
invocations by the resolved binary path. The match SHALL operate on the path resolved by
the sandbox backend (e.g. via `shutil.which` or an absolute path), not on the
agent-supplied command name. This is distinct from the `command` kind which matches the
agent input field before resolution.

#### Scenario: binary-exclusion-blocks-resolved-binary-path

- **WHEN** a `run_in_sandbox` invocation resolves to `/usr/bin/curl` and a scope exclusion
  with `kind="binary"` and `value="/usr/bin/curl"` is active
- **THEN** the invocation is refused with a denial reason naming the binary path

#### Scenario: binary-exclusion-allows-different-binary-same-name

- **WHEN** a `run_in_sandbox` invocation resolves to `/usr/local/bin/curl` and a scope
  exclusion blocks only `/usr/bin/curl`
- **THEN** the invocation is allowed (match is against the resolved path, not the basename)

#### Scenario: binary-exclusion-ignored-when-block-dynamic-false

- **WHEN** a `binary` scope exclusion has `block_dynamic=False`
- **THEN** the `check_exclusion` helper returns `None` regardless of the binary path

### Requirement: Filesystem path exclusion blocks tool access to sensitive paths

The scope exclusion system SHALL support a `filesystem_path` kind that blocks static tool
access to paths matching the exclusion value. Tools affected SHALL include at minimum
`read_file`, `grep`, `scip_index`, and `run_in_sandbox` `input_files` paths. The match
SHALL apply independently of the repo-root path-escape check.

#### Scenario: filesystem-path-exclusion-blocks-git-directory-access

- **WHEN** a scope exclusion has `kind="filesystem_path"` and `value=".git/**"` and a tool
  attempts to read `.git/config`
- **THEN** the tool invocation is refused

#### Scenario: filesystem-path-exclusion-allows-unrelated-paths

- **WHEN** a scope exclusion blocks `.git/**` and a tool reads `src/main.py`
- **THEN** the read is allowed

### Requirement: Host machine is never in scope

The machine hosting the sandbox SHALL NOT be treated as a reachable target for any scan
operation. Privilege escalation checks, dynamic validation, and any prove or exploit
activity SHALL execute exclusively within the sandbox environment.

#### Scenario: sandbox-execution-confined-to-sandbox-environment

- **WHEN** any prove or exploit activity executes a command or binary
- **THEN** the execution is confined to the sandbox; host processes, filesystems, and
  network interfaces are not accessible as targets

#### Scenario: privilege-escalation-checks-operate-inside-sandbox-only

- **WHEN** a privilege escalation check runs
- **THEN** it attempts escalation only within the sandbox, never against the host kernel or
  host processes

### Requirement: Unknown scope exclusion kinds are rejected at parse time

Scan profile parsing SHALL reject unknown scope exclusion kinds at load time. An unknown
kind SHALL cause profile validation to fail with an error message listing the valid kinds.

#### Scenario: unknown-kind-causes-parse-failure

- **WHEN** a scan profile contains a scope exclusion with `kind="made_up_kind"`
- **THEN** profile validation fails with an error listing valid kinds

#### Scenario: valid-kinds-parse-successfully

- **WHEN** a scan profile contains only recognized kinds (`route`, `path_glob`,
  `functional_area`, `vuln_class`, `command`, `binary`, `filesystem_path`)
- **THEN** profile validation succeeds