## 1. ContextInjectorPlugin protocol

- [x] 1.1 (Red) Wrote `tests/unit/test_context_injector_base.py`: an object with `plugin_type=CONTEXT_INJECTOR`, `attack_classes`, `priority`, and `inject_context(attack_class, task, repo_type)` satisfies `isinstance(obj, ContextInjectorPlugin)`; an object missing `inject_context` does not.
- [x] 1.2 Added `ContextInjectorPlugin(Plugin, Protocol)` to `src/quarry_plugins/base.py`: `attack_classes: frozenset[VulnerabilityClass]`, `priority: int`, `inject_context(attack_class: VulnerabilityClass, task: AgentTask, repo_type: str) -> str | None`.
- [x] 1.3 `task test` green (1424 passed); ruff + pyright clean.

## 2. Context budget enforcement

- [x] 2.1 (Red) Wrote `tests/unit/test_context_budget.py`: an over-budget block truncates at the boundary, ends with a trailing note, and the truncation flag is `True`; an under-budget (and exactly-at-budget) block is returned verbatim with the flag `False`.
- [x] 2.2 Added `src/quarry_plugins/budget.py`: `enforce_context_budget(text: str, max_tokens: int = 500) -> tuple[str, bool]` using a deterministic char-count heuristic (4 chars/token).
- [x] 2.3 `task test` green; ruff + pyright clean.

## 3. Priority-ordered assembly

- [x] 3.1 (Red) Wrote `tests/unit/test_context_assembly.py`: two plugins with priorities 100 and 50 both matching → the priority-50 block appears first in the assembled text; a plugin returning `None` or not matching `attack_class` contributes nothing and is excluded from the contributing-names list; a plugin's over-budget output is truncated in the assembled result; labeled-block format verified.
- [x] 3.2 Added `assemble_domain_context(plugins, attack_class, task, repo_type) -> tuple[str, list[str]]` to `src/quarry_plugins/budget.py`: filters to plugins whose `attack_classes` contains the class and whose `inject_context()` is non-`None`, sorts ascending by `priority`, applies `enforce_context_budget` per block, concatenates as `## Domain context: {name}`, returns `(assembled_text, contributing_names)`.
- [x] 3.3 `task test` green; ruff + pyright clean.

## 4. Schema + quarry.toml plumbing for plugins_active

- [x] 4.1 (Red) Wrote `tests/unit/test_plugins_active_config.py`: `ScanDefaultsConfig.plugins_active` defaults to `[]`; a `quarry.toml` `[scan_defaults]` `plugins_active = ["multitenant_isolation"]` round-trips through `load_quarry_config`; `local_scan_profile(plugins_active=[...])` sets `ScanProfile.plugins_active`; `AgentTask.domain_context` defaults to `""` and round-trips.
- [x] 4.2 Added `plugins_active: list[str] = Field(default_factory=list)` to `ScanDefaultsConfig` (`src/quarry/panel_config.py`).
- [x] 4.3 Added a `plugins_active: list[str] | None = None` parameter to `local_scan_profile()` (`src/quarry/schemas.py`), defaulting to `[]` when unset — mirrors the `integration_configs` parameter added for `lifecycle-hooks`.
- [x] 4.4 Added `AgentTask.domain_context: str = ""` to `src/quarry/schemas.py`, parallel to the existing `recon_notes` field.
- [x] 4.5 `task test` green (1439 passed); ruff + pyright clean.

## 5. Wire quarry.toml → RunScanInput → ScanProfile.plugins_active

- [x] 5.1 (Red) Wrote `tests/unit/test_plugins_active_wiring.py` (mirroring `tests/unit/test_benchmark_no_integrations.py`'s `client_context` fixture pattern, monkeypatching `quarry_server.routers.scans.load_quarry_config` to isolate the wiring from real file I/O): a scan started with a `QuarryConfig` whose `scan_defaults.plugins_active = ["multitenant_isolation"]` results in `RunScanInput.plugins_active == ["multitenant_isolation"]`; the no-config-override default case is `[]`.
- [x] 5.2 Added `plugins_active: list[str] = []` to `RunScanInput` (`src/quarry_workflows/run_scan.py`); populated it at the API layer (`src/quarry_server/routers/scans.py`) from `quarry_config.scan_defaults.plugins_active`; threaded it into both `local_scan_profile(...)` call sites via `plugins_active=scan_input.plugins_active`.
- [x] 5.3 `task test` green (1442 passed); ruff + pyright clean.

## 6. Wire emit_agent_tasks: compute domain_context per task

- [x] 6.1 (Red) Wrote `tests/unit/test_emit_agent_tasks_domain_context.py`: given a fake `CONTEXT_INJECTOR` plugin discoverable via a monkeypatched entry-point, and `plugins_active` containing its name, `emit_agent_tasks` stamps non-empty `domain_context` onto matching tasks; with `plugins_active=[]` (default) or a name not in the allowlist, every emitted task's `domain_context` is `""` and the plugin is never called; dict-style invocation also handles `plugins_active`.
- [x] 6.2 In `src/quarry_activities/emit_agent_tasks.py`: accepts a `plugins_active: list[str] | None` argument (positional + dict-style); when non-empty, loads plugins via `load_plugins()` + `plugins_of_type(..., PluginType.CONTEXT_INJECTOR)`, filters to those whose `name` is in `plugins_active`, and for each task calls `assemble_domain_context(matching_plugins, vc, task, arch_doc.repo_type)`, stamping the result onto `task.domain_context` via `model_copy`.
- [x] 6.3 Updated the `emit-agent-tasks` activity call site in `src/quarry_workflows/run_scan.py` to pass `scan.profile.plugins_active` as an additional arg.
- [x] 6.4 `task test` green (1446 passed); ruff + pyright clean.

## 7. Wire hunt_impl and hunt prompt templates

- [x] 7.1 (Red) Wrote `tests/unit/test_hunt_domain_context_variable.py`: `hunt_impl`'s rendered prompt for a task with non-empty `domain_context` contains that text, and it lands outside the real `<target_content>...</target_content>` evidence block (had to fix the test's own boundary-detection: the system prompt's prose literally contains the substring `<target_content>` descriptively, with no matching close tag, so a naive first-`.index()` search picks the wrong "tag" — used `rindex` bounded by the real close tag instead); a task with empty `domain_context` renders with no `"Domain context"` text anywhere.
- [x] 7.2 Added `"domain_context": task.domain_context` to the `variables` dict in `src/quarry_activities/hunt.py`.
- [x] 7.3 Added `{% if domain_context | default("") %}...{{ domain_context }}...{% endif %}` to the developer part of `prompts/hunt/hunt.1.0.0.j2` (after `recon_notes`, before `task_prompt`) and, via a scripted find/replace against the identical `recon_notes`→`task_prompt` boundary text shared by all templates, to all 17 per-class templates in `prompts/hunt/`. Verified via `grep -n domain_context prompts/hunt/*.j2` — 18 files, 2 lines each (36 total).
- [x] 7.4 Ran `task prompt-lint` — `OK — no prompt text in Python source`.
- [x] 7.5 `task test` green (1448 passed; also re-ran `test_hunt_activity.py`, `test_emit_agent_tasks.py`, and the golden suite specifically to confirm the template edits changed nothing else); ruff + pyright clean.

## 8. OSS reference stub plugins

- [x] 8.1 (Red) Wrote `tests/unit/test_context_injector_stubs.py`: `multitenant_isolation.inject_context(..., repo_type="saas-multitenant")` returns non-`None` placeholder text; `repo_type="web_service"` returns `None`; `template_injection.inject_context(VulnerabilityClass.SSTI, ..., repo_type="template-heavy")` returns non-`None`; wrong `attack_class` or wrong `repo_type` each return `None`.
- [x] 8.2 Added `src/quarry_plugins/context/multitenant_isolation.py` (`attack_classes=frozenset(VulnerabilityClass)` — isolation matters across classes, not just one) and `src/quarry_plugins/context/template_injection.py` (`attack_classes=frozenset({SSTI})`) — each a small class + module-level singleton (mirroring the `SLACK_NOTIFY_HOOK` pattern), placeholder text only, `priority=100` for both (no ordering dependency between them).
- [x] 8.3 Registered both under `[project.entry-points."quarry.plugins"]` in `pyproject.toml`, tagged `plugin_type=CONTEXT_INJECTOR`.
- [x] 8.4 `uv sync`; verified via `load_plugins()` + `plugins_of_type(..., PluginType.CONTEXT_INJECTOR)` that both resolve (`['multitenant_isolation', 'template_injection']`).
- [x] 8.5 `task test` green (1455 passed); ruff + pyright clean.

## 9. Benchmark safety

- [x] 9.1 (Red) Wrote `tests/unit/test_benchmark_no_context_injection.py`: a `TestEffectivePluginsActive` suite testing the new pure helper directly (benchmark forces `[]`; non-benchmark passes through) plus a source-inspection guard that both `local_scan_profile(...)` call sites route through it; an API-level test confirms `RunScanInput.benchmark` reaches the workflow input even with a non-empty `quarry.toml` `plugins_active`.
- [x] 9.2 Added `effective_plugins_active(plugins_active, *, benchmark) -> list[str]` to `src/quarry_workflows/run_scan.py` (sibling to `should_dispatch_lifecycle_hooks`); both `local_scan_profile(...)` call sites now pass `plugins_active=effective_plugins_active(scan_input.plugins_active, benchmark=scan_input.benchmark)` instead of the raw value — reuses the existing `benchmark: bool` flag threaded end-to-end from `lifecycle-hooks`.
- [x] 9.3 `task test` green (1459 passed); ruff + pyright clean.

## 10. Provenance (contributing plugin names)

- [x] 10.1 (Red) Wrote `tests/unit/test_domain_context_provenance.py`: `AgentTask.domain_context_sources` defaults to `[]`; `emit_agent_tasks` records `["multitenant_isolation"]` when that plugin contributes; records `[]` when the plugin is active but doesn't match the repo.
- [x] 10.2 Added `AgentTask.domain_context_sources: list[str] = []` to `src/quarry/schemas.py`; `emit_agent_tasks` now captures `assemble_domain_context`'s second return value (previously discarded as `_sources`) and stamps both fields together via `model_copy`.
- [x] 10.3 `task test` green (1462 passed); ruff + pyright clean.

## 11. End-to-end verification

- [x] 11.1 Wrote `tests/integration/test_context_injector_e2e.py`, chaining the REAL entry-point-discovered plugins (no `importlib.metadata` monkeypatching — both OSS stubs genuinely resolve via `pyproject.toml`), the real `emit_agent_tasks` activity, and the real `hunt_impl` prompt-rendering path: a `saas-multitenant` repo with `plugins_active=["multitenant_isolation"]` produces a hunt task whose rendered prompt contains `## Domain context: multitenant_isolation`. (A full `RunScanWorkflow` e2e wasn't used — same reason as `lifecycle-hooks`: post pure-agentic-pivot, every existing e2e scan test relies on a `MockModelClient` yielding zero findings, and real `repo_type` inference only happens inside the full agentic recon pipeline this change doesn't otherwise touch. Workflow wiring itself isn't in scope here since injection happens entirely inside `emit_agent_tasks`/`hunt_impl`, both exercised directly and for real.)
- [x] 11.2 Golden portability test in the same file: a `web_service` (generic) repo with **both** OSS stubs in `plugins_active` renders zero `## Domain context:` blocks anywhere — both stubs correctly silent off-target, confirmed via `emit_agent_tasks`' output (`domain_context == ""`, `domain_context_sources == []`) and the actual rendered prompt text.
- [x] 11.3 `uv run ruff format .` (319 files unchanged); full `task test` green (**1465 passed**); full-repo `uv run pyright` clean (0 errors); `task prompt-lint` still OK.
