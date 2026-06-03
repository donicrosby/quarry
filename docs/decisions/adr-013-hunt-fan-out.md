# ADR 013: Hunt fan-out topology and the pure-agentic pivot

## Status

Accepted

## Context

Week 12 turns candidate generation fully agentic. The prior approach ran three separate
deterministic Temporal activities per vuln class (secrets regex scanner, IDOR ast-pattern
detector, command-injection source-to-sink detector) against FastAPI route extracts. This
is FastAPI-only and non-transferable to Go, Node, or C/C++ targets.

The core questions:

1. How many hunters run, and with what scope?
2. Where does the concurrency cap live — workflow or activity?
3. How does budget compose across parallel hunters?
4. When does a hunter stop — iteration count or token cost?
5. How does the focus allowlist interact with hunters?
6. What happens to findings that match an out-of-scope exclusion?
7. How does provider selection work without scattering `if provider == "mock"` branches?
8. How are stage commits kept atomic as new stages are added?

## Decision

### One hunter per (vuln_class, scope)

Recon produces a list of `AgentTask`s — one per `(vuln_class, scope)` pair where `scope`
is a subsystem name or root path from the `ArchitectureDoc`. Each hunter reasons about one
class in one scope, producing `list[CandidateFinding]`. This is preferred over a single
all-class hunter per scope (reasoning quality degrades with task breadth) or one hunter per
vuln class across all scopes (no structural locality for large repos).

### Pure-agentic: remove ATTACK_SURFACE and static detectors

`ATTACK_SURFACE` (`extract-fastapi-routes-for-repo`) is removed. It was FastAPI/Python
`ast`-only and produced `attack_surface_items` consumed only by the deterministic detectors.
The three static detector activities (`scan-repo-for-secrets`, `scan-attack-surface-for-idor`,
`scan-attack-surface-for-command-injection`) are removed. Hunters become the sole candidate
generators, taking their input from `ArchitectureDoc.entry_points` which is language-agnostic.

Retained: the validation/proof activities (`validate-secret-candidate`,
`validate-idor-candidate`, `validate-command-injection-candidate`). These operate on
`CandidateFinding`s regardless of how they were generated.

**The redaction scrubber (`quarry_models/redaction.py`) and the leaked-secret guard are NOT
removed.** They are a security boundary, not a detector. Every tool result passes through
`scrub()` before entering the model context. Hunters flag hardcoded-secret candidates from
the presence of `[REDACTED_SECRET_N]` markers in tool output — never from raw secret values.

New pipeline: `CREATED → SNAPSHOT → RECON → HUNT → VALIDATION → COVERAGE → REPORT →
INTEGRATING → COMPLETED`.

### Concurrency cap in the workflow, not the activity

`hunt_stage` (in `quarry_workflows/hunt_stage.py`) wraps `workflow.execute_activity` calls
in an `asyncio.Semaphore(hunt_max_concurrent)` gather. This lives in workflow code as a pure
data-flow operation, which keeps it replay-deterministic. If the cap were inside the activity,
it would require shared mutable state across concurrent activity executions — incompatible with
Temporal's execution model.

Default: `hunt_max_concurrent = 8`.

### Two deterministic drops before fan-out

Before the semaphore gather, tasks are filtered in order:

1. **Focus drop.** Any `AgentTask` whose `vuln_class` is not in `ScanProfile.vuln_classes`
   is dropped. This is the structural enforcement of `--focus`; the prompt also carries an
   advisory "Focus only on: [classes]" line, but the advisory alone is not the guarantee.
2. **Exclusion drop.** Any task whose `vuln_class` appears in the union of
   `ScanProfile.scope_exclusions` and `TargetAuthorization.do_not_test` is dropped.
   Exclusion always wins over focus.

Both drops are pure Python operations on the task list in workflow code — no model calls,
no activities. This keeps them replay-deterministic.

Post-hunt: any `CandidateFinding` whose file path or route matches a `route`, `path_glob`,
or `functional_area` exclusion receives `triage_label = "oos"` and is not promoted to
`FinalFinding`.

### Budget: iteration count is the primary stop, dollar cap is a ceiling

`hunt_max_iterations` (default 12) is the expected stop. When `scan.budget_cap_usd` is
`None`, each `HuntActivity` receives `BudgetSpec(max_cost_usd=None)`, so the loop is bounded
purely by iterations. When a budget is set, it is sliced proportionally
(`budget_cap_usd / len(tasks)`) and passed as a ceiling — no artificial floor. A floor would
risk `budget_exceeded` stopping the loop before it has used its iteration budget.

### Provider enum + factory

Provider selection uses `Provider(StrEnum)` (members `MOCK = "mock"`, `LITELLM = "litellm"`)
and `build_model_client(provider: Provider, ...) -> ModelClient` in
`quarry_models/factory.py`. `RoleConfig.provider` coerces its `str` value to `Provider` at
parse time. Adding a new vendor (e.g. `BEDROCK` in Week 15) is a new enum member and a new
`case` in the factory — no scattered `if provider == ...` branches across activity files.

`recon_subsystem.py` reads the resolved `recon` panel role and calls the factory. The default
panel uses `provider = "mock"`, so all existing tests are unaffected.

### Atomic stage commits via child workflow

Each stage's output persistence and marker advancement were previously separate calls; a
crash between them could leave a stage marked complete without its data (or vice versa).
`CommitStageWorkflow` (child workflow in `quarry_workflows/commit_stage.py`) performs both
operations in a single transactional `persist-scan-state` activity call (one DB transaction),
applied to new `RECON` and `HUNT` boundaries.

### Entry-points loader

`quarry_tools/registry.py` exposes `load_registry()` which merges `BUILTIN_REGISTRY` with
tools discovered via `importlib.metadata.entry_points(group="quarry.tools")`. Extension tools
(`opengrep`, `treesitter_query`) are registered in `pyproject.toml` under this group. The
loop is unchanged — it does not care what is in the registry.

## Consequences

- The scan workflow has no class-specific Python logic for candidate generation. Adding a new
  vuln class to the hunt path is: add the `VulnerabilityClass` enum member + a class-keyed
  prompt template entry. No new Temporal activity needed unless a new validator is required.
- `attack_surface_items`, `AttackSurfaceItemRecord`, and the three static-detector activities
  are removed from the codebase. Any external code that depended on them will break.
- The coverage ledger now counts `AgentTask`s scanned/skipped per vuln_class/scope (with skip
  reasons: `dropped-by-focus`, `dropped-by-exclusion`, `hunter-error`) instead of FastAPI routes.
- `RoleConfig.provider` becomes a validated enum, not a free string — TOML configs using
  unknown provider names will fail fast at parse time, which is the correct behaviour.
