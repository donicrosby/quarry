## ADDED Requirements

### Requirement: Binary analysis tools registered in tool registry

Six binary analysis tools SHALL be registered in the tool registry, each
declaring its name, input schema, and role allowlist. A missing external binary
SHALL raise `ToolUnavailableError` rather than crashing the agent loop.

#### Scenario: tools-are-discoverable-in-registry

- **WHEN** the tool registry is loaded
- **THEN** `file_type`, `extract_strings`, `checksec`, `linked_libraries`,
  `suid_sgid_detect`, and `symlink_analysis` are present
- **AND** each has a non-empty description, input schema, and roles list

#### Scenario: missing-external-binary-raises-tool-unavailable

- **WHEN** a binary analysis tool is invoked but its external binary (e.g.
  `file` or `readelf`) is not on PATH
- **THEN** the tool raises `ToolUnavailableError` with a message naming the
  missing binary and an install hint

### Requirement: File type detection

The `file_type` tool SHALL determine a binary's MIME type and architecture by
wrapping the system `file` command. For any file in the repo root it SHALL
return a human-readable classification.

#### Scenario: elf-binary-is-detected

- **WHEN** `file_type` is run against a compiled ELF binary
- **THEN** the output includes "ELF" and the architecture (e.g. x86-64)

#### Scenario: non-binary-file-is-classified

- **WHEN** `file_type` is run against a text file
- **THEN** the output describes it as text (not an error)

### Requirement: Printable strings extraction

The `extract_strings` tool SHALL extract sequences of printable ASCII or UTF-8
characters from a binary. It SHALL accept a configurable minimum string length
(default 4) and SHALL return each string on its own line.

#### Scenario: strings-are-extracted-with-default-min-length

- **WHEN** `extract_strings` is run against a binary containing embedded text
- **THEN** contiguous printable sequences of length >= 4 are returned

#### Scenario: configurable-min-length-is-honored

- **WHEN** `extract_strings` is called with `min_length=8`
- **THEN** only sequences of length >= 8 appear in the output

### Requirement: Hardening audit for ELF binaries

The `checksec` tool SHALL inspect an ELF binary and report the status of RELRO
(Full/Partial/None), NX/DEP, PIE/ASLR, stack canary, and RPATH/RUNPATH. It
SHALL wrap `readelf` for section/segment inspection.

#### Scenario: fully-hardened-binary-reports-all-protections

- **WHEN** `checksec` is run against an ELF binary compiled with full RELRO,
  NX, PIE, and stack canary
- **THEN** RELRO reports "Full", NX reports "Enabled", PIE reports
  "Enabled", and stack canary reports "Enabled"

#### Scenario: unhardened-binary-reports-missing-protections

- **WHEN** `checksec` is run against an ELF binary compiled without
  hardening flags
- **THEN** at least one protection field reports "None" or "Disabled"

### Requirement: Linked library inventory

The `linked_libraries` tool SHALL list the dynamically linked shared libraries
of an ELF binary by wrapping `readelf -d`. For each library it SHALL report
the soname.

#### Scenario: dynamically-linked-binary-lists-libraries

- **WHEN** `linked_libraries` is run against a dynamically linked ELF binary
- **THEN** each linked shared library soname appears in the output

#### Scenario: statically-linked-binary-reports-none

- **WHEN** `linked_libraries` is run against a statically linked binary
- **THEN** the output indicates no dynamic libraries

### Requirement: SUID and sgid bit detection

The `suid_sgid_detect` tool SHALL walk the repo root and report every regular
file with the setuid or setgid permission bit set. Each hit SHALL include the
repo-relative path and the octal permission bits.

#### Scenario: suid-binary-is-reported

- **WHEN** a regular file in the repo root has the setuid bit (`chmod u+s`)
- **THEN** `suid_sgid_detect` reports it with its path and `4xxx` permission

#### Scenario: no-suid-files-reports-empty

- **WHEN** no file under the repo root has SUID or sgid bits
- **THEN** `suid_sgid_detect` reports zero findings

### Requirement: Symlink and hardlink analysis

The `symlink_analysis` tool SHALL walk the repo root and report every symbolic
link and hard link, including the link path and its resolved target. Hard links
SHALL be detected by comparing inode numbers.

#### Scenario: symlink-is-reported-with-target

- **WHEN** a symlink exists in the repo root
- **THEN** `symlink_analysis` reports the link path and its target path

#### Scenario: hardlink-is-detected-via-inode

- **WHEN** two paths in the repo root share the same inode (hard link count > 1)
- **THEN** `symlink_analysis` reports both paths as hard-linked

### Requirement: Binary analysis activity feeds hunt stage

A Temporal activity `binary_analysis` SHALL execute a deterministic pass over
the repo root, invoke the binary analysis tools for every discovered binary,
and produce a structured report persisted as a scan artifact. A
`ContextInjectorPlugin` targeting `attack_classes=[security_misconfiguration]`
SHALL read the persisted report artifact and inject it as domain context on
every `security_misconfiguration` `AgentTask`, including tasks emitted by
gapfill and reachability-feedback.

#### Scenario: activity-produces-and-persists-structured-report

- **WHEN** `binary_analysis` runs against a repo containing at least one ELF
  binary
- **THEN** the returned report includes a per-binary section with file type,
  hardening flags, linked libraries, and any SUID/sgid or symlink findings
- **AND** the report is persisted as an artifact for later consumption by
  the context injector

#### Scenario: report-is-injected-via-context-injector

- **WHEN** a `security_misconfiguration` hunt task is assembled via
  `assemble_domain_context` during `emit-agent-tasks`
- **THEN** the `BinaryAnalysisContextInjector` plugin reads the persisted
  report and contributes it to the task's `domain_context`
- **AND** the task's `domain_context_sources` includes `binary_analysis`

#### Scenario: gapfill-and-feedback-tasks-receive-binary-context

- **WHEN** gapfill or reachability-feedback emits a
  `security_misconfiguration` `AgentTask`
- **THEN** the task's `domain_context` includes the binary analysis report
  from the persisted artifact

#### Scenario: no-binaries-yields-empty-report

- **WHEN** `binary_analysis` runs against a repo with no binary artifacts
- **THEN** the activity returns an empty report without error

### Requirement: Read-only and repo-root confined

Every binary analysis tool SHALL be read-only and SHALL operate only within
the repository root. Path confinement SHALL be enforced by the existing
`ToolRunner` (src/quarry_tools/runner.py:41-50).

#### Scenario: path-escape-is-refused-by-runner

- **WHEN** a binary analysis tool input specifies a path outside the repo root
- **THEN** `ToolRunner` raises `ToolSecurityError` before the tool executes

#### Scenario: tool-never-writes-files

- **WHEN** any binary analysis tool is invoked
- **THEN** it does not create, modify, or delete any file in the repository