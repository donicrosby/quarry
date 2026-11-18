## ADDED Requirements

### Requirement: Deterministic tempfile-race scanner

A deterministic scanner activity registered under `quarry_plugins.vuln_classes` SHALL regex-scan source files for unsafe tempfile patterns: predictable names in `/tmp` or `/var/tmp`, deprecated APIs (`tempfile.mktemp()`, `os.tmpnam()`, C `tmpnam()`), and `mktemp` invocations lacking `--tmpdir` or using a fixed template prefix.

#### Scenario: predictable-tmp-name-is-detected

- **WHEN** a source file contains an `open()` call constructing a path under `/tmp` with a predictable name component
- **THEN** the scanner emits a candidate finding citing the file and line

#### Scenario: deprecated-mktemp-api-is-detected

- **WHEN** a source file calls `tempfile.mktemp()` or `tmpnam()`
- **THEN** the scanner emits a candidate finding with evidence kind `deprecated_tempfile_api`

#### Scenario: safe-tempfile-usage-is-not-flagged

- **WHEN** a source file uses `tempfile.mkstemp()` or `mktemp --tmpdir`
- **THEN** the scanner produces no candidate for that line

### Requirement: Deterministic terminal-escape scanner

A deterministic scanner activity registered under `quarry_plugins.vuln_classes` SHALL regex-scan source files for unsanitized terminal-output patterns: user-controlled data reaching `print()`/`echo`/`printf`/`write()` to stdout/stderr without an ANSI-escape-stripping pass, in CLI-facing code paths.

#### Scenario: unsanitized-print-of-user-input-is-detected

- **WHEN** a source file echoes user-controlled input to stdout in a CLI handler via `print()` or `echo` without escape filtering
- **THEN** the scanner emits a candidate finding with evidence kind `unsanitized_terminal_output`

#### Scenario: sanitized-output-is-not-flagged

- **WHEN** a source file strips ANSI escape sequences from user input before printing
- **THEN** the scanner produces no candidate for that line