# Change: cli-context-injector-prompts

## Why

The context-injector plugin subsystem (protocol, budget enforcement, assembly, reference
plugins) is fully implemented and specced, but an operator has no CLI surface for it.
Plugins are configured only through a `quarry.toml` `plugins_active` list — there is no
`quarry plugin list` to see what is installed, no `quarry plugin show` to inspect
capabilities, no `--plugins-active` flag on `quarry scan run` to override the toml, and
no way to preview what domain context a plugin would inject for a given attack class and
repo type. The operator is blind to a subsystem that directly shapes hunt prompt content.

## What Changes

- **`quarry plugin list`**: A new CLI command that lists every installed plugin (all
  plugin types, not just context-injectors) with name, type, version, and — for
  context-injector plugins — attack classes and priority.
- **`quarry plugin show <name>`**: A new CLI command that prints full detail of one
  named plugin, including its protocol attributes.
- **`quarry scan run --plugins-active <name,...>`**: A new CLI flag on the existing
  `scan run` command that overrides the `quarry.toml` `plugins_active` list. The flag
  is carried through the `StartScanRequest` API and flows into the workflow's
  `plugins_active` field, taking precedence over the toml default.
- **Server API**: `StartScanRequest` gains an optional `plugins_active` field. The
  server merges it: CLI-provided list overrides `quarry.toml`; absent list uses the
  toml default (backward-compatible).
- **`quarry context-injector preview`**: A new CLI command that runs
  `assemble_domain_context` as a dry run for a given `--attack-class` and
  `--repo-type`, printing the rendered domain context text and the list of
  contributing plugin names — so an operator can verify what a scan WILL inject
  before running it.

## Impact

- **Specs**: `cli-and-tui` (ADDED five requirements covering the four new commands and
  the server API contract).
- **Code**: `src/quarry_cli/main.py` (new `plugin_app` typer and commands,
  `--plugins-active` flag on `run_scan`), `src/quarry_server/schemas.py`
  (`plugins_active` field on `StartScanRequest`), `src/quarry_server/routers/scans.py`
  (merge logic: CLI overrides toml), `src/quarry_client/client.py` (optional
  `plugins_active` param on `start_scan`).
- **Threat model**: The four new CLI commands are read-only inspection or local dry-run
  — they exercise no new trust boundary. The `--plugins-active` flag flows through the
  existing API and scan-start path; it adds no new privilege (the operator already
  controls `quarry.toml`) and the server's merge logic is a simple list preference
  with no injection surface.
- **Non-goals**: Plugin hot-reload (the registry is entry-points-based and loaded at
  activity time); a TUI plugin panel (separate change); a `quarry plugin enable/disable`
  command (the plugin list is already namespaced — activation is the scan flag);
  modifying the benchmark suppression path (VERIFIED at
  b284af7:src/quarry_workflows/run_scan.py:3487-3496 — benchmark runs already force
  `plugins_active` to empty regardless of input).

## Reconcile notes (2026-09-10 original vs b284af7 main)

- **Dropped**: "Dry-run prompt rendering that shows the full hunt prompt with domain
  context injected" — the full hunt prompt rendering requires the prompt registry,
  template variables, and evidence chunks that only exist at scan time; `quarry
  context-injector preview` shows the domain context block alone, which is the
  operator's actionable concern. Full-prompt preview would be a separate change
  touching `build_prompt` and every hunt template. "Plugin hot-reload" — the registry
  is entry-points-based and loaded once per activity; live reload is a separate
  architectural concern. "Plugin enable/disable subcommand" — activation is per-scan
  via `--plugins-active`; persistent enable/disable is `quarry.toml`.
- **Kept**: Plugin listing, plugin inspection, `--plugins-active` scan flag, domain
  context dry-run preview. The core need — CLI visibility into what context-injector
  plugins exist and what they will produce — is genuinely absent from main (zero plugin
  commands in `src/quarry_cli/main.py` at b284af7:831 lines, VERIFIED by grep).
- **Rescoped**: Plugin listing covers ALL plugin types (the registry already discovers
  them; restricting to context-injectors only would add a filter that hides useful
  information). The `--plugins-active` flag takes a comma-separated list matching the
  existing `--focus` flag pattern, not a repeated `--plugin` flag — this keeps the
  CLI consistent with `--focus` and avoids an extra typer option style.

## Review revision (adversarial review r1)

- **`plugins-active-flag-overrides-toml` (blocker)**: the scenario's THEN asserted hunt
  tasks "carry domain context" — an outcome the `--plugins-active` flag does not control.
  `multitenant_isolation.inject_context` fires only when recon classifies
  `repo_type == "saas-multitenant"` (a model-produced `ArchitectureDoc` value, not set by
  the flag or toml). Re-scoped the THEN to the deterministic claim: the CLI sends
  `plugins_active: ["multitenant_isolation"]` in `StartScanRequest`, overriding the empty
  toml default. Whether that override then yields domain context in hunt tasks is governed
  by the already-landed `context-injector` spec (the `plugins_active` allowlist plus the
  plugin's own `repo_type`/`attack_class` match), not by this flag.
- **plugin inspect requirement (should-fix)**: scoped the attribute enumeration so
  `attack_classes`/`priority`/`inject_context` are listed only for context-injector
  plugins (matching task 4.3), and added a `plugin show` scenario for a non-context-injector
  tool plugin (`opengrep`) printing only name/version/type.