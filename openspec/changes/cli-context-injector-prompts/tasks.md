# Tasks: cli-context-injector-prompts

## 1. Server: StartScanRequest gains plugins_active field
- [ ] 1.1 Add `plugins_active: list[str] | None = None` to `StartScanRequest` in `src/quarry_server/schemas.py` (VERIFIED current schema at b284af7:src/quarry_server/schemas.py:11-35)
- [ ] 1.2 In `src/quarry_server/routers/scans.py:start_scan()`, merge: if `body.plugins_active is not None`, use it; else fall back to `quarry_config.scan_defaults.plugins_active` (VERIFIED current merge point at b284af7:src/quarry_server/routers/scans.py:130)
- [ ] 1.3 RED: test that posting `StartScanRequest` with `plugins_active: ["dummy"]` passes `["dummy"]` into the workflow input; test that omitting `plugins_active` uses the toml default

## 2. QuarryClient: start_scan accepts plugins_active
- [ ] 2.1 Add optional `plugins_active: list[str] | None = None` parameter to `QuarryClient.start_scan()` in `src/quarry_client/client.py` (VERIFIED current signature at b284af7:src/quarry_client/client.py:49-58)
- [ ] 2.2 Pass `plugins_active` through in the POST JSON body alongside existing fields
- [ ] 2.3 RED: unit test that the client POSTs the field when set and omits it when None

## 3. CLI: quarry plugin list command
- [ ] 3.1 Create `plugin_app = typer.Typer(help="Inspect installed plugins.")` and register it as `app.add_typer(plugin_app, name="plugin")` in `src/quarry_cli/main.py`
- [ ] 3.2 Implement `@plugin_app.command("list")` that calls `load_plugins()` from `quarry_plugins.registry` (VERIFIED at b284af7:src/quarry_plugins/registry.py:20-37), iterates all plugins, and prints a tabular listing: name, type, version, and for context-injectors the attack_classes and priority
- [ ] 3.3 The command SHALL NOT require a running server (it loads entry-points locally)
- [ ] 3.4 RED: integration test with the two shipped OSS reference plugins installed — verify output includes `multitenant_isolation` and `template_injection` with correct attributes

## 4. CLI: quarry plugin show command
- [ ] 4.1 Implement `@plugin_app.command("show")` accepting a `name: str` argument
- [ ] 4.2 Load the named plugin via `load_plugins()` lookup by `plugin.name`; if not found, print error and `raise typer.Exit(1)`
- [ ] 4.3 Print all protocol attributes: name, version, plugin_type, attack_classes (if context-injector), priority (if context-injector), and the `inject_context` method signature/docstring for context-injector plugins
- [ ] 4.4 The command SHALL NOT require a running server
- [ ] 4.5 RED: test `quarry plugin show multitenant_isolation` prints correct attributes; test `quarry plugin show opengrep` prints only name/version/type; test `quarry plugin show nonexistent` exits 1

## 5. CLI: --plugins-active flag on scan run
- [ ] 5.1 Add `--plugins-active` option to `@scan_app.command("run")` in `src/quarry_cli/main.py`, typed as `str | None`, help describing comma-separated plugin names
- [ ] 5.2 Parse the flag: `plugins = [p.strip() for p in plugins_active.split(",") if p.strip()]` when set, `None` when omitted
- [ ] 5.3 Thread `plugins_active` through `_run_scan_command()` → `QuarryClient.start_scan(plugins_active=...)` → server
- [ ] 5.4 RED: test that `quarry scan run --plugins-active foo,bar --repo /tmp/x` sends `["foo", "bar"]` in the API request; test that omitting the flag sends `None`
- [ ] 5.5 Verify benchmark runs still suppress: confirm `benchmark_local` and `benchmark_cybergym` paths do not accept or forward a `--plugins-active` flag (ASSUMED: these paths force empty, coder must verify existing `effective_plugins_active` guard is downstream of CLI override)

## 6. CLI: quarry context-injector preview command
- [ ] 6.1 Create `ci_app = typer.Typer(help="Context-injector dry-run utilities.")` and register as `app.add_typer(ci_app, name="context-injector")` in `src/quarry_cli/main.py`
- [ ] 6.2 Implement `@ci_app.command("preview")` accepting `--attack-class` (str, required) and `--repo-type` (str, required)
- [ ] 6.3 Validate `--attack-class` against `VulnerabilityClass` enum values (VERIFIED at b284af7:src/quarry/schemas.py); print valid classes and exit 1 on invalid input
- [ ] 6.4 Load all context-injector plugins, construct a synthetic `AgentTask` with dummy values for required fields id/scan_id/role/task_name plus scope (required fields per `src/quarry/schemas.py:771-775`), call `assemble_domain_context()` (VERIFIED at b284af7:src/quarry_plugins/budget.py:33-63), print the assembled context text and the list of contributing plugin names
- [ ] 6.5 The command SHALL NOT require a running server
- [ ] 6.6 RED: test `quarry context-injector preview --attack-class ssti --repo-type template-heavy` shows the template_injection block; test `--attack-class xss --repo-type generic` shows empty output

## 7. Verification and landing
- [ ] 7.1 Ruff + pyright (strict) clean on all changed files
- [ ] 7.2 `npx openspec validate cli-context-injector-prompts --strict` green
- [ ] 7.3 Run existing tests to confirm no regression: `uv run pytest tests/ -x -q`
- [ ] 7.4 Manual smoke: `quarry plugin list` prints at least the two OSS reference plugins
- [ ] 7.5 Manual smoke: `quarry context-injector preview --attack-class ssti --repo-type template-heavy` prints a domain context block
- [ ] 7.6 Conventional commit + push