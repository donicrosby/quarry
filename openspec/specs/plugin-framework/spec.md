# plugin-framework Specification

## Purpose

Quarry is extended without modifying its core: plugins are discovered through
entry points, validated at load, and given a uniform identity and lifecycle. This
is the substrate the concrete plugin kinds (lifecycle hooks, context injectors)
build on, so that adding a capability means shipping a package rather than patching
the pipeline.

## Requirements

### Requirement: Unified plugin protocol
The system SHALL define a single `Plugin` protocol with `name`, `version`, and `plugin_type`
attributes, and a `PluginType` enumeration covering at least `tool`, `finding_sink`, and
`lifecycle_hook`. Any object implementing these attributes SHALL satisfy the protocol.

#### Scenario: Object satisfies the Plugin protocol
- **WHEN** an object defines `name: str`, `version: str`, and `plugin_type: PluginType`
- **THEN** `isinstance(object, Plugin)` returns `True`

#### Scenario: Object missing a required attribute does not satisfy the protocol
- **WHEN** an object is missing `plugin_type`
- **THEN** `isinstance(object, Plugin)` returns `False`

### Requirement: Plugin discovery via a single entry-point group
The system SHALL discover all plugins exclusively through the `quarry.plugins` Python
entry-points group. The system SHALL NOT load plugins from arbitrary filesystem paths.

#### Scenario: Plugin registered via entry-point is discovered
- **WHEN** a package registers a plugin object under the `quarry.plugins` entry-point group
- **THEN** `load_plugins()` returns an object satisfying the `Plugin` protocol with a matching
  `name`

#### Scenario: No entry-points registered
- **WHEN** no packages register anything under `quarry.plugins`
- **THEN** `load_plugins()` returns an empty list without raising

### Requirement: Fail-soft plugin loading
The system SHALL isolate a failure loading one plugin from all other plugins: if a single
entry-point raises during load, that plugin is skipped and all other plugins still load.

#### Scenario: One plugin fails to load, others still load
- **WHEN** two plugins are registered under `quarry.plugins` and one raises an exception during
  `entry_point.load()`
- **THEN** `load_plugins()` returns the successfully-loaded plugin and does not raise

### Requirement: Agent tool registry sources from the unified loader
The agent tool registry SHALL derive its `tool`-typed plugins from the unified `quarry.plugins`
loader (merged with built-in tools), while preserving the existing tool registry's public
return type and the set of tools it previously returned via the `quarry.tools` group.

#### Scenario: Previously available tools remain available after migration
- **WHEN** the tool registry is loaded after migrating tool registration onto `quarry.plugins`
- **THEN** the returned registry still contains the `opengrep` and `treesitter_query` tools and
  all built-in tools

### Requirement: Finding-sink registry sources from the unified loader
The finding-sink list (`default_sinks()`) SHALL derive its `finding_sink`-typed plugins from the
unified `quarry.plugins` loader, while preserving the existing set of default sinks and the
existing end-of-scan delivery behavior.

#### Scenario: Previously available sinks remain available after migration
- **WHEN** `default_sinks()` is called after migrating sink registration onto `quarry.plugins`
- **THEN** the returned list still contains the `file`, `jira_dry_run`, and `slack_dry_run` sinks
