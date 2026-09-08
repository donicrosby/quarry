## ADDED Requirements

### Requirement: Context-injector plugin protocol
The system SHALL define a `ContextInjectorPlugin` protocol extending `Plugin` with
`attack_classes: frozenset[VulnerabilityClass]`, `priority: int`, and
`inject_context(attack_class, task, repo_type) -> str | None`.

#### Scenario: Object satisfies the ContextInjectorPlugin protocol
- **WHEN** an object defines `plugin_type=context_injector`, `attack_classes`, `priority`, and
  `inject_context(attack_class, task, repo_type)`
- **THEN** `isinstance(object, ContextInjectorPlugin)` returns `True`

### Requirement: Portability — no output for a non-matching target
A context-injector plugin SHALL return `None` from `inject_context` when the given `repo_type`
or `attack_class` does not match what the plugin targets. The assembly mechanism SHALL contribute
nothing to the prompt for a plugin that returns `None`.

#### Scenario: Off-target plugin contributes nothing
- **WHEN** `inject_context` is called with a `repo_type` the plugin does not target
- **THEN** it returns `None`

#### Scenario: Off-target plugin is excluded from assembled output
- **WHEN** assembling domain context for a task, and one of the candidate plugins returns `None`
- **THEN** that plugin's name does not appear in the assembled text or the contributing-plugin list

### Requirement: Context budget enforced in code
Each contributed context block SHALL be capped at a fixed token budget (heuristic: ~4 characters
per token), enforced in code before the block is used — never expressed only as a prompt
instruction. A block exceeding the budget SHALL be truncated at the boundary with a trailing
note, and the truncation SHALL be recorded, never silent.

#### Scenario: Over-budget block is truncated with a recorded note
- **WHEN** a plugin's `inject_context` returns text exceeding the configured token budget
- **THEN** the assembled block is truncated at the budget boundary, ends with a truncation note,
  and the truncation is flagged in the return value

#### Scenario: Under-budget block is unchanged
- **WHEN** a plugin's `inject_context` returns text within the token budget
- **THEN** the assembled block is used verbatim

### Requirement: Priority-ordered, labeled assembly
The system SHALL concatenate contributed blocks from multiple matching context-injector plugins
in ascending `priority` order, each labeled `## Domain context: {name}`.

#### Scenario: Two matching plugins are ordered by ascending priority
- **WHEN** two plugins with `priority` values 100 and 50 both match the same attack class and task
- **THEN** the priority-50 plugin's labeled block appears before the priority-100 plugin's block
  in the assembled text

### Requirement: Domain context reaches the hunt prompt
The hunt prompt-rendering flow SHALL include each hunt task's assembled domain context as a
distinct, non-empty-by-default template variable, rendered in the prompt's instruction
(developer) part — never wrapped as untrusted `<target_content>` evidence.

#### Scenario: A hunt task with assembled domain context renders it in the prompt
- **WHEN** a hunt `AgentTask` carries non-empty assembled domain context
- **THEN** the rendered hunt prompt's developer part contains that context, outside any
  `<target_content>` block

#### Scenario: A hunt task with no domain context renders unchanged
- **WHEN** a hunt `AgentTask` carries no domain context (the default)
- **THEN** the rendered hunt prompt is unaffected — no empty or placeholder domain-context section
  appears

### Requirement: Context injectors are disabled unless explicitly activated
The system SHALL NOT invoke any context-injector plugin's `inject_context` for a scan unless that
plugin's name appears in the scan's resolved `plugins_active` allowlist. `plugins_active` SHALL
default to empty.

#### Scenario: No plugins_active entries means no injector output
- **WHEN** a scan's `plugins_active` is empty (the default)
- **THEN** no context-injector plugin's `inject_context` is called for that scan

#### Scenario: An explicitly activated plugin is invoked
- **WHEN** a scan's `plugins_active` includes a registered context-injector plugin's name
- **THEN** that plugin's `inject_context` is called for matching hunt tasks

### Requirement: No external side effects during benchmark runs
A benchmark-configured scan SHALL have `plugins_active` forced to empty, enforced by the system,
regardless of any otherwise-active quarry.toml configuration — so no hunt prompt in a benchmark
run ever contains injected domain context.

#### Scenario: Benchmark scan renders no domain-context blocks
- **WHEN** a scan is constructed via the benchmark profile path, even if `quarry.toml` configures
  a non-empty `plugins_active`
- **THEN** the resulting scan's `plugins_active` is empty and no hunt prompt contains a
  `## Domain context:` block

### Requirement: Reference OSS stub plugins ship with placeholder content only
The system SHALL provide two reference context-injector plugins — `multitenant_isolation`
(matches `repo_type == "saas-multitenant"`) and `template_injection` (matches
`repo_type == "template-heavy"` and `attack_class == VulnerabilityClass.SSTI`) — both returning
placeholder text only, never real domain invariants.

#### Scenario: multitenant_isolation fires only on a matching repo
- **WHEN** `inject_context` is called with `repo_type == "saas-multitenant"`
- **THEN** it returns a non-`None`, placeholder-labeled block

#### Scenario: multitenant_isolation is silent on a generic repo
- **WHEN** `inject_context` is called with a `repo_type` other than `"saas-multitenant"`
- **THEN** it returns `None`

#### Scenario: template_injection requires both repo_type and attack_class to match
- **WHEN** `inject_context` is called with `repo_type == "template-heavy"` but
  `attack_class != VulnerabilityClass.SSTI`
- **THEN** it returns `None`
