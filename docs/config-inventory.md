# Configuration Inventory

The single canonical map of every configuration knob a contributor or operator
needs. Four areas: prompt templates, panel config, profile / `scan_defaults`,
and budget. Every claim cites `file:line` — if a behavior here can't be
grepped, it doesn't belong here. Line numbers are against `origin/main @
840a9ec`; re-grep after rebases.

---

## 1. Prompt templates

### 1.1 Storage and versioning rules

- Templates live under `prompts/<role>/<name>.<version>.j2`, loaded by
  `PromptRegistry.load(role, name, version)` which resolves the path as
  `{prompts_root}/{role}/{name}.{version}.j2`
  (`src/quarry_prompts/registry.py:67-73`).
- The default `prompts_root` is the repo's `prompts/` directory
  (`src/quarry_prompts/__init__.py:15`); `get_registry()` is a cached
  singleton (`src/quarry_prompts/__init__.py:18-26`).
- A missing template raises `TemplateNotFoundError` at load time
  (`src/quarry_prompts/registry.py:74-78`) — there is no silent fallback to a
  different version.
- Templates are rendered in a `jinja2.sandbox.SandboxedEnvironment` with
  `StrictUndefined` (fail-fast on missing variables, SSTI blocked)
  (`src/quarry_prompts/registry.py:60-65`).
- Every loaded template is hash-tracked: `PromptTemplateRef` carries
  `id = "{role}/{name}"`, `version`, and `sha256` (hex SHA-256 of the raw
  template bytes) (`src/quarry_prompts/registry.py:18-24`, digest computed at
  `src/quarry_prompts/registry.py:84-85`). The hash is emitted in the
  provenance header prepended to the rendered system message
  (`src/quarry_prompts/build_prompt.py:87`).

**Versioning rule:** templates are versioned artifacts. A behavioral change =
a **new file** with a bumped version (e.g. `validate.1.3.0.j2`), plus a bump
of the pinning constant in code. **Never edit a versioned template in place**
— the `sha256` in `PromptTemplateRef` is the provenance trail, and editing in
place rewrites history while keeping the old version label.

### 1.2 Version pins in code

Only the validate ensemble uses named module constants; every other call site
passes the version as a string literal at the `build_prompt()` call.

| Constant / literal | Value | Where pinned | Template file(s) it selects |
|---|---|---|---|
| `VALIDATE_PROMPT_VERSION` | `"1.2.0"` | `src/quarry_activities/validate.py:144` (used at `:318`) | `prompts/validate/validate.1.2.0.j2` |
| `REFUTE_PROMPT_VERSION` | `"1.3.0"` | `src/quarry_activities/validate.py:145` (used at `:181`) | `prompts/validate/refute.1.3.0.j2` |
| `_TASK_PROMPT_VERSION` | `"1.0.0"` | `src/quarry_activities/emit_agent_tasks.py:26` (used at `:43`) | `prompts/task/<class>.1.0.0.j2`, fallback `prompts/task/default.1.0.0.j2` |
| `_EXPLORATORY_PROMPT_VERSION` | `"1.0.0"` | `src/quarry_activities/gapfill.py:64` (used at `:96`) | `prompts/task/explore.1.0.0.j2` |

The refute template name is overridable per tier via
`ModelTier.prompt_regime` (`src/quarry/panel_config.py:75`, consumed at
`src/quarry_activities/validate.py:180`) — the *version* stays pinned to
`REFUTE_PROMPT_VERSION` regardless.

### 1.3 Full template directory map

Roles with a **per-class** template set try the class-named template first and
fall back to the role's generic/default template:

- **hunt** — `prompts/hunt/<vuln_class>.1.0.0.j2` with fallback to
  `prompts/hunt/hunt.1.0.0.j2`
  (`src/quarry_activities/hunt.py:236-256`). Per-class files exist for:
  auth, command_injection, csrf, file_upload, idor,
  insecure_deserialization, insecure_design, ldap_injection,
  mass_assignment, open_redirect, path_traversal, secrets,
  security_misconfiguration, sql_injection, ssrf, ssti, weak_crypto, xss,
  xxe.
- **task** — `prompts/task/<vuln_class>.1.0.0.j2` with fallback to
  `prompts/task/default.1.0.0.j2` (`src/quarry_activities/emit_agent_tasks.py:37-49`;
  `TemplateNotFoundError` triggers the fallback at `:46-47`). Same per-class
  list as hunt, minus csrf/file_upload/hunt-named entries, plus
  `default` and `explore`.
- **dynamic_validate** — `prompts/dynamic_validate/<vuln_class>.1.0.0.j2`
  with fallback to `prompts/dynamic_validate/dynamic_validate.1.0.0.j2`
  (`src/quarry_activities/dynamic_validate.py:119-131`). Per-class files:
  auth, command_injection, csrf, file_upload, idor, open_redirect,
  sql_injection, ssrf, ssti, xss, xxe.

Single-template roles (name = role, version literal `"1.0.0"` at the call):

| Role | Template | Call site |
|---|---|---|
| gapfill | `prompts/gapfill/gapfill.1.0.0.j2` | `src/quarry_activities/gapfill.py:356-360` |
| calibrate | `prompts/calibrate/calibrate.1.0.0.j2` | `src/quarry_activities/calibrate.py:207-211` |
| exploit | `prompts/exploit/exploit.1.0.0.j2` | `src/quarry_activities/exploit.py:126-130` |
| prove | `prompts/prove/prove.1.0.0.j2` | `src/quarry_activities/prove.py:98-102` |
| trace | `prompts/trace/trace.1.0.0.j2` | `src/quarry_activities/tracer.py:204-206` |
| live_recon | `prompts/live_recon/live_recon.1.0.0.j2` | `src/quarry_activities/live_recon.py:140-144` |
| recon (knowledge base) | `prompts/recon/knowledge_base.1.0.0.j2` | `src/quarry_activities/kb_recon.py:355-359` |
| recon (subsystem) | `prompts/recon/subsystem.1.0.0.j2` | `src/quarry_activities/recon_subsystem.py:140-144` |

Partial-template roles — these carry only a developer section, are exempt
from the system-part requirement (`src/quarry_prompts/build_prompt.py:42`),
and are injected into a larger message structure rather than sent as a system
prompt:

| Role | Template | Call site |
|---|---|---|
| `_feedback` (vagueness guard) | `prompts/_feedback/vague_reasoning.1.0.0.j2` | `src/quarry_models/loop.py:165-167` |
| `_feedback` (schema repair) | `prompts/_feedback/schema_repair.1.0.0.j2` | `src/quarry_models/loop.py:199-201` |
| `_envelope` (4 partials) | `prompts/_envelope/{developer,evidence,output_schema,system}.j2` | shared envelope macros, referenced from `src/quarry_prompts/build_prompt.py:5,19` |

The validate role's multiple on-disk versions (`validate.1.0.0/1.1.0/1.2.0`,
`refute.1.0.0/1.1.0/1.2.0/1.3.0`) are history: only the pinned versions are
loaded. Version rationale is documented at
`src/quarry_activities/validate.py:138-143` (v1.1.0 presence-based clause for
secrets claims; v1.2.0 redaction-disclosure notice).

---

## 2. Panel config (`quarry.toml` `[panels.<name>.roles.<role>]`)

### 2.1 File loading — `load_quarry_config`

`src/quarry/panel_config.py:320-345`. Search order, first hit wins:

1. Explicit `path` argument (`:332-334`)
2. `quarry.toml` in the current working directory (`:335`)
3. `~/.config/quarry/quarry.toml` (`:336`)
4. All-defaults `QuarryConfig()` if none found (`:345`) — i.e. the mock panel.

Credential-like top-level keys (matching `^[A-Z][A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD|_CREDENTIAL)$`,
`src/quarry/panel_config.py:49`) are rejected at parse time with `ValueError`
(`_check_for_credentials`, `:307-317`). Never put API keys in `quarry.toml`.

### 2.2 Resolution — `resolve_panel`

`src/quarry/panel_config.py:348-361`. The built-in `DEFAULT_PANEL` is copied,
then the named panel's `roles` dict overrides it **role-by-role** (`:354-359`).
Unspecified roles keep their DEFAULT_PANEL entry.

**Silent-mock-fallback hazard:** if `panel_name` is `None`/empty, **or the
named panel does not exist in the config**, the function returns the
all-mock `DEFAULT_PANEL` with **zero warnings** (`:351-352`, docstring).
Likewise, a role omitted from the named panel silently stays mock. Every
DEFAULT_PANEL role is `Provider.MOCK, model="mock-v1", rpm=30`
(`src/quarry/panel_config.py:154-174`). A typo in `QUARRY_PANEL` or a missing
`[panels.<name>]` table therefore runs the entire scan against the mock
provider and produces synthetic findings — always verify the panel snapshot
recorded on the scan (`panel_entries`, stamped at
`src/quarry_server/routers/scans.py:62-74`).

### 2.3 Panel selection — `QUARRY_PANEL`

- `QuarrySettings.panel: str = ""` (`src/quarry/config.py:38`);
  `QuarrySettings` uses `env_prefix="QUARRY_"`
  (`src/quarry/config.py:13`), so `QUARRY_PANEL` is the environment variable
  that selects the panel. Empty string → DEFAULT_PANEL.
- Consumed by the API layer: `resolve_panel(quarry_config, settings.panel)`
  at `src/quarry_server/routers/scans.py:56-57`.
- `docker-compose.yml:37,68` forwards `QUARRY_PANEL` into the server and
  worker services; `docs/dev-log/2026-06-11-hardening-gate.md:98` records the
  incident where the container fell back to the mock panel because
  `quarry.toml` wasn't mounted.

### 2.4 Role and tier schema

- `RoleConfig` fields (`src/quarry/panel_config.py:85-105`): `provider`
  (default MOCK), `model` (default `""`), `rpm` (default 30),
  `turn_timeout_seconds` (default 120), `tool_call_cap` (default None),
  `thinking_budget_tokens` (default None), `tiers` (default empty list).
- `ModelTier` fields (`src/quarry/panel_config.py:65-78`): `kind`
  (`reasoner` / `debater` / `counterpoint`, `TierKind` at `:52-62`),
  `provider`, `model`, `rpm`, `turn_timeout_seconds`, `prompt_regime`,
  `tool_call_cap`, `thinking_budget_tokens`.
- A role without `tiers` is an implicit one-entry reasoner tier
  (`resolve_tier`, `src/quarry/panel_config.py:108-127`).
- `vendor_allowlist` (see §3) is enforced against every role's provider and
  every tier's provider before any model call
  (`enforce_vendor_allowlist`, `src/quarry/panel_config.py:130-151`; called
  at `src/quarry_server/routers/scans.py:61`).

### 2.5 DEFAULT_PANEL roles

Eleven roles, all `Provider.MOCK / mock-v1 / rpm=30`
(`src/quarry/panel_config.py:155-174`): `recon`, `hunt`, `validate`,
`calibrate`, `gapfill`, `prove`, `trace`, `report`, `dynamic_validate`,
`live_recon`, `exploit`.

---

## 3. Profile / `[scan_defaults]`

### 3.1 `ScanDefaultsConfig` field reference

`src/quarry/panel_config.py:190-248`. All fields are consumed by the API
layer and forwarded into `RunScanInput` at
`src/quarry_server/routers/scans.py:102-124`.

| Field (TOML `[scan_defaults]`) | Default | Effect |
|---|---|---|
| `focus_classes` | `[]` (`:193`) | Declared config default for scan focus. **Currently not consumed anywhere** — no reader outside the model itself (grep `scan_defaults.focus_classes` finds only the declaration). See §3.2. |
| `hunt_max_iterations` | 12 (`:194`) | Agent-loop iteration cap per hunt task. |
| `hunt_max_concurrent` | 8 (`:195`) | Semaphore bound on concurrent per-class hunt tasks. |
| `validate_max_concurrent` | 8 (`:198`) | Semaphore bound on concurrent candidate validations in AGENTIC_VALIDATE. |
| `trace_max_concurrent` | 4 (`:201`) | Per-finding tracer fan-out bound. |
| `calibrate_max_concurrent` | 4 (`:203`) | Per-finding severity-calibration fan-out bound. |
| `prove_max_concurrent` | 4 (`:208`) | Per-finding PROVE attempt-loop fan-out bound (cruft-purge §3.2). |
| `dynamic_validate_max_concurrent` | 8 (`:212`) | Pre-hunt inventory sweep: how many classes' propose→dispatch→capture chains may overlap. `1` restores historical serial behavior. |
| `validate_max_iterations` | 20 (`:213`) | Iteration cap per validation loop. |
| `gapfill_max_iterations` | 20 (`:214`) | Iteration cap per gapfill loop. |
| `recon_max_iterations` | 40 (`:215`) | Iteration cap for recon loops. |
| `dedup_max_iterations` | 8 (`:216`) | Iteration cap for the dedup pass. |
| `max_coverage_rounds` | 3 (`:220`) | Cap on iterative coverage-loop rounds (ADR-022); loop halts sooner on convergence or budget exhaustion. |
| `coverage_yield_threshold` | 0.15, range [0.0, 1.0] (`:227`) | Rising-bar early stop: a round must add ≥ `max(1, ceil(f × cumulative_findings))` new distinct findings to justify another round. `0.0` disables. |
| `exploratory_injection_fraction` | 0.3, range [0.0, 0.5] (`:234-236`; bound `EXPLORATORY_INJECTION_MAX_FRACTION = 0.5` at `:44`) | Fraction of each gapfill pass spent on open-ended exploratory investigations. `0.0` disables. |
| `seed` | None (`:239`) | Fixed scan seed; None derives a deterministic seed from the scan_id UUID (resolved at `src/quarry_server/routers/scans.py:117`). |
| `plugins_active` | `[]` (`:243`) | Names of context-injector plugins active for scans. Disabled-by-default invariant: empty = no plugins. |
| `vendor_allowlist` | `[]` (`:247`) | Allowed model vendors for the panel; empty = unrestricted. Enforced fail-fast by `enforce_vendor_allowlist` before any model call (`src/quarry_server/routers/scans.py:61`). |

Adjacent config blocks parsed from the same file (`QuarryConfig`,
`src/quarry/panel_config.py:316-325`): `[budget]` (§4), `[retry]`
(`max_attempts`, default 4, clamped ≥ 1, plus the seconds-scale backoff
intervals `initial_interval_seconds` 2.0, `backoff_coefficient` 2.0,
`maximum_interval_seconds` 30.0, `jitter_fraction` 0.2 — bounded [0.0, 0.5] —
and `calibrate_start_to_close_seconds` 300, the per-attempt StartToClose
budget for the `calibrate-finding` agent-loop activity; all wired through
`RunScanInput` by `src/quarry_server/routers/scans.py` into the workflow's
`RetryPolicy` (cruft-purge §3.7 — `RetryConfig`, `:245-278`; counts
unchanged, intervals seconds-scale),
`[integrations.<name>]` (`IntegrationTomlEntry`, `:283-293`; secrets must be
`${secret:ENV_VAR}` templates, enforced at `:364-383`), `[scan]`
(`reasoning_lexicon` banned-phrase/evidence overrides, `ScanConfig` /
`ReasoningLexiconConfig`, `:261-280`).

### 3.2 Focus resolution and the `--focus` semantics hazard

Resolution lives in `resolve_focus` (`src/quarry/panel_config.py:386-429`):
precedence is CLI flag > config list > `default` (all `VulnerabilityClass`
values when `default=None`, `:398-399`). Unknown class tokens and empty
resolved sets raise `ValueError` (`:411-414`, `:424-427`).

**Hazard — omitting `--focus` does NOT scan all classes.** The chain:

1. CLI: `--focus` omitted → `focus_classes = None` and `resolve_focus` is
   never even called (`src/quarry_cli/main.py:103-110`). The CLI help text
   ("Omit to scan all classes", `src/quarry_cli/main.py:56`) is inaccurate.
2. Client sends an empty list (`src/quarry_client/client.py:66`).
3. The workflow builds the scan profile via `local_scan_profile(...,
   vuln_classes=scan_input.vuln_classes or None, ...)`
   (`src/quarry_workflows/run_scan.py:414-417`), and `local_scan_profile`
   hardcodes the fallback
   `[SECRETS, IDOR, COMMAND_INJECTION]`
   (`src/quarry/schemas.py:1855-1860`, profile id `"local-fast"` at `:1853`).

So an unfocused scan covers exactly **secrets, idor, command_injection**.
Note that `[scan_defaults].focus_classes` (§3.1) does **not** participate:
neither the CLI (`resolve_focus(cli_focus=tokens, config_focus=[])` at
`src/quarry_cli/main.py:107`), the TUI (`config_focus=[]` at
`src/quarry_tui/screens/scan_launch.py:92-95`), nor the API server passes it.
The TUI's own default is an explicit all-classes checkbox set
(`src/quarry_tui/screens/scan_launch.py:82-89`). `QuarrySettings.focus_classes`
/ `QUARRY_FOCUS_CLASSES` (`src/quarry/config.py:39`) is likewise declared but
has no consumer outside the settings model.

---

## 4. Budget (`[budget]`)

### 4.1 Fields

`BudgetConfig` (`src/quarry/panel_config.py:183-187`):

- `max_cost_per_scan_usd: float | None = None` — per-scan cumulative cost cap.
- `max_tokens_per_scan: int | None = None` — declared but has **no
  enforcement consumer** (grep finds only the declaration; no reader in
  `src/quarry_server` or `src/quarry_workflows`). Setting it does nothing
  today.

### 4.2 Enforcement points for `max_cost_per_scan_usd`

1. **Ingestion**: the API router passes
   `budget_cap_usd=quarry_config.budget.max_cost_per_scan_usd` into
   `RunScanInput` (`src/quarry_server/routers/scans.py:101`; field declared
   at `src/quarry_workflows/run_scan.py:275`).
2. **Per-agent-loop (per-iteration)**: each activity converts the cap into a
   `BudgetSpec(max_cost_usd=...)` (`src/quarry_models/types.py:91-93`; e.g.
   `src/quarry_activities/calibrate.py:345`, `src/quarry_activities/prove.py:220`,
   `src/quarry_activities/tracer.py:347`, `src/quarry_activities/gapfill.py:565`;
   note `kb_recon.py:482` substitutes a hardcoded `1.0` when the cap is
   None). The agent loop checks **after each iteration, after executing that
   turn's tool calls**: `if budget_spec.max_cost_usd is not None and
   total_cost >= budget_spec.max_cost_usd` → returns
   `stop_reason="budget_exceeded"` (`src/quarry_models/loop.py:690-699`).
   The cap can be exceeded by the in-flight iteration's cost — it is a
   post-iteration halt, not a reservation system.
3. **Per-stage (workflow level)**: the workflow re-reads cumulative persisted
   spend (`_scan_cost_so_far`, `src/quarry_workflows/run_scan.py:3263-3273`)
   and calls `budget_decision(cap, spent)` before each agentic stage; when
   over budget the stage is skipped and marked budget-overrun but the scan
   continues to the next stage (`budget_decision` and its docstring at
   `src/quarry_workflows/run_scan.py:3248-3260`). Call sites: gapfill
   (`:850`), post-coverage-round (`:984`), hunt (`:1483`), validate
   (`:1719`), dedup (`:2257`), prove (`:2330`). `cap=None` disables gating
   entirely (`:3257-3258`).

---

## Appendix — other env-var knobs (`QuarrySettings`)

`src/quarry/config.py:6-54`, all with `QUARRY_` prefix: `server_url`,
`temporal_address`, `task_queue`, `server_host`, `server_port`,
`server_no_worker`, `db_path`, `default_provider`, `default_model`,
`prompt_retention`, `redaction_enabled`, `validate_checklist_enabled`
(default True; consumed at `src/quarry_activities/validate.py:532`),
`config_file`, `panel` (§2.3), `focus_classes` (§3.2 — unconsumed),
`artifact_backend` / `redis_url` / `s3_bucket`, `sandbox_backend` /
`sandbox_image`. Provider API keys (e.g. `CHUTES_API_KEY`) are read by the
model clients from the environment, never from `quarry.toml` (§2.1).
