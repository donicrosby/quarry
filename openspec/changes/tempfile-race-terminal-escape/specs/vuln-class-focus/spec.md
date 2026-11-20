## ADDED Requirements

### Requirement: tempfile_race vulnerability class

`tempfile_race` SHALL be a recognized `VulnerabilityClass` covering unsafe creation of temporary files in shared directories: predictable names in `/tmp` or `/var/tmp`, deprecated tempfile APIs (`tempfile.mktemp()`, `os.tmpnam()`, `tmpnam()`), and TOCTOU windows where an attacker can pre-plant a file between name generation and open.

#### Scenario: tempfile-race-is-focusable

- **WHEN** an operator passes `--focus tempfile_race`
- **THEN** the scan hunts only tempfile-race candidates

#### Scenario: tempfile-race-is-listed-in-valid-classes

- **WHEN** an invalid focus value is rejected
- **THEN** `tempfile_race` appears in the list of valid classes

### Requirement: terminal_escape vulnerability class

`terminal_escape` SHALL be a recognized `VulnerabilityClass` covering attacker-controlled input echoed to a terminal device (stdout/stderr) without ANSI/terminal-control-sequence sanitization, allowing cursor manipulation, screen clearing, or escape-sequence injection.

#### Scenario: terminal-escape-is-focusable

- **WHEN** an operator passes `--focus terminal_escape`
- **THEN** the scan hunts only terminal-escape candidates

#### Scenario: terminal-escape-is-listed-in-valid-classes

- **WHEN** an invalid focus value is rejected
- **THEN** `terminal_escape` appears in the list of valid classes