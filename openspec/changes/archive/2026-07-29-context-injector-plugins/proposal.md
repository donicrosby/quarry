## Why

The unified plugin subsystem (`plugin-framework`, `lifecycle-hooks`) shipped the *reaction* half
of the roadmap's "domain plugins" capability — hooks that react to a scan event — but not the
*context-injection* half the original roadmap actually emphasized: plugins that inject
domain-specific guidance (e.g. multi-tenant isolation invariants, template-injection context)
into the hunt prompt for a matching repo, and silently do nothing for a non-matching one.
`PluginType.CONTEXT_INJECTOR` exists today only as an unused enum member — no protocol, no
loader wiring, no prompt integration. This change finishes that half using the scaffolding
(`Plugin`, `PluginType`, the `quarry.plugins` entry-point loader) already built for it.

## What Changes

- Add a `ContextInjectorPlugin` protocol (`plugin_type=CONTEXT_INJECTOR`) with
  `attack_classes: frozenset[VulnerabilityClass]`, `priority: int`, and
  `inject_context(attack_class, task, repo_type) -> str | None`.
- Add a code-enforced context budget (~500 tokens per block, deterministic char-count heuristic)
  and a priority-ordered assembly helper that filters to matching plugins, calls each, and
  concatenates labeled blocks (`## Domain context: {name}`).
- Wire injection into the hunt flow: `emit_agent_tasks` (which already has
  `ArchitectureDoc.repo_type`) computes each task's domain context and stamps it onto a new
  `AgentTask.domain_context` field; `hunt_impl` threads it into the Jinja `variables` dict; every
  hunt prompt template (generic + all per-class templates) renders it in the developer part,
  distinct from `<target_content>` evidence.
- Ship two reference OSS stub plugins with **placeholder text only**: `multitenant_isolation`
  (fires only when `repo_type == "saas-multitenant"`) and `template_injection` (fires only when
  `repo_type == "template-heavy"` and `attack_class == VulnerabilityClass.SSTI`).
- Enforce the existing portability invariant: a plugin whose `repo_type`/`attack_class` doesn't
  match returns `None` and contributes nothing — verified by a golden portability test against a
  generic repo.
- Record which plugins contributed to a given hunt task for provenance (contributing plugin
  names), and continue to force `plugins_active = []` for benchmark scans (extending the existing
  benchmark-safety invariant from `lifecycle-hooks` to this new plugin type).

## Capabilities

### New Capabilities
- `context-injector`: the `ContextInjectorPlugin` protocol, budget/assembly helpers, hunt-flow
  wiring (`AgentTask.domain_context` → hunt prompt templates), and the two OSS reference stubs.

### Modified Capabilities
(none — `plugin-framework`'s `PluginType` requirement already says "covering at least tool,
finding_sink, and lifecycle_hook," leaving room for `context_injector` without a spec change)

## Impact

- **Code**: `src/quarry_plugins/base.py` (new `ContextInjectorPlugin` protocol), new
  `src/quarry_plugins/budget.py`, new `src/quarry_plugins/context/` stub plugins
  (`multitenant_isolation.py`, `template_injection.py`), `src/quarry/schemas.py`
  (`AgentTask.domain_context`), `src/quarry_activities/emit_agent_tasks.py` (context computation),
  `src/quarry_activities/hunt.py` (thread `domain_context` into template variables),
  `prompts/hunt/*.j2` (all 18 templates — generic + 17 per-class), `pyproject.toml`
  (`[project.entry-points."quarry.plugins"]` additions), CLI benchmark profile construction
  (force `plugins_active = []`).
- **Dependencies**: none new.
- **Systems**: none — this is a prompt-construction-time addition, no new network egress, no new
  persisted entity beyond one new `AgentTask` field.
- **Docs**: extends `docs/decisions/adr-025-unified-plugin-subsystem.md`'s scope, or a small
  follow-on ADR — decided in design.md.
