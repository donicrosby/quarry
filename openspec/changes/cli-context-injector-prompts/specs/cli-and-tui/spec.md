## ADDED Requirements

### Requirement: CLI plugin listing command

The CLI SHALL provide a `quarry plugin list` command that loads all installed plugins
via the entry-points registry and prints each plugin name, type, and version. For
context-injector plugins it SHALL also show attack classes and priority. The command
SHALL succeed without a running server.

#### Scenario: plugin-list-shows-all-installed-plugins

- **WHEN** `quarry plugin list` is invoked with context-injector and tool plugins installed
- **THEN** the output includes both plugin names and types, with context-injector
  plugins additionally showing attack classes and priority

#### Scenario: plugin-list-succeeds-without-server

- **WHEN** `quarry plugin list` is invoked with no Quarry server running
- **THEN** it prints the plugin list and exits 0

### Requirement: CLI plugin inspect command

The CLI SHALL provide a `quarry plugin show <name>` command that loads the named plugin
from the entry-points registry and prints its protocol attributes: name, version, and
plugin_type for every plugin, plus attack_classes, priority, and the inject_context
signature for context-injector plugins. Missing plugin SHALL exit 1.

#### Scenario: plugin-show-prints-full-detail-for-context-injector

- **WHEN** `quarry plugin show multitenant_isolation` is invoked
- **THEN** it prints the plugin name, version, type `context_injector`, attack classes,
  priority, and the `inject_context` method signature or docstring

#### Scenario: plugin-show-prints-base-attributes-for-non-context-injector

- **WHEN** `quarry plugin show opengrep` is invoked for the tool plugin `opengrep`
- **THEN** it prints name, version, and type `tool`, with no attack classes, priority, or
  inject_context signature

#### Scenario: plugin-show-missing-exits-with-error

- **WHEN** `quarry plugin show nonexistent_plugin` is invoked
- **THEN** it exits with code 1 and prints an error message naming the missing plugin

### Requirement: CLI scan run --plugins-active flag

The `quarry scan run` command SHALL accept a `--plugins-active` flag taking a
comma-separated list of plugin names. When set, the CLI SHALL pass the list through
StartScanRequest to the server, where it overrides the quarry.toml plugins_active
default. Absent flag SHALL leave behavior unchanged.

#### Scenario: plugins-active-flag-overrides-toml

- **WHEN** `quarry scan run --plugins-active multitenant_isolation --repo <path>` is invoked
  with `quarry.toml` `plugins_active` empty
- **THEN** the CLI sends `plugins_active: ["multitenant_isolation"]` in the `StartScanRequest`
  — the flag value, overriding the empty toml default

#### Scenario: plugins-active-flag-absent-leaves-behavior-unchanged

- **WHEN** `quarry scan run --repo <path>` is invoked without `--plugins-active`
- **THEN** the scan uses `quarry.toml` `plugins_active` as before (backward-compatible)

#### Scenario: plugins-active-flag-respects-benchmark-suppression

- **WHEN** placed in a benchmark run path, even if `--plugins-active` is set on the CLI
- **THEN** `plugins_active` is forced to empty (ASSUMED: the existing
  `effective_plugins_active` guard at run_scan.py:3487 applies downstream; coder must
  verify the guard fires after CLI override, not before)

### Requirement: Server StartScanRequest accepts plugins_active

The server StartScanRequest SHALL accept an optional plugins_active field. When non-None,
the server SHALL use it as the scan active plugin list. When None, the server SHALL fall
back to quarry.toml scan_defaults.plugins_active. Benchmark scans SHALL still force
plugins_active to empty per effective_plugins_active.

#### Scenario: server-honors-client-provided-plugins-active

- **WHEN** `StartScanRequest` posts with `plugins_active: ["multitenant_isolation"]`
- **THEN** the scan workflow receives `plugins_active=["multitenant_isolation"]`,
  overriding the toml default

#### Scenario: server-falls-back-to-toml-when-field-absent

- **WHEN** `StartScanRequest` posts with `plugins_active` omitted (None)
- **THEN** the scan workflow receives the `quarry.toml` `scan_defaults.plugins_active`
  value (backward-compatible with existing clients)

### Requirement: CLI context-injector preview command

The CLI SHALL provide a `quarry context-injector preview` command accepting
--attack-class (required) and --repo-type (required). It SHALL load all context-injector
plugins, call assemble_domain_context with a synthetic AgentTask, print the assembled
text, and list contributing plugin names. The command SHALL succeed without a running
server.

#### Scenario: preview-shows-domain-context-for-matching-plugins

- **WHEN** `quarry context-injector preview --attack-class ssti --repo-type template-heavy` is invoked
- **THEN** the output includes the `## Domain context: template_injection` block with
  placeholder text, and lists `template_injection` as a contributing plugin

#### Scenario: preview-shows-empty-when-no-plugin-matches

- **WHEN** `quarry context-injector preview --attack-class xss --repo-type generic` is invoked
  and no installed plugin matches both
- **THEN** the output shows empty domain context and an empty contributing-plugins list,
  exiting 0

#### Scenario: preview-succeeds-without-server

- **WHEN** `quarry context-injector preview --attack-class ssti --repo-type template-heavy` is
  invoked with no Quarry server running
- **THEN** it prints the domain context and contributing plugins, and exits 0