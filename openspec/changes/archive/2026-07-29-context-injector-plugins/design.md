## Context

`plugin-framework` (this repo's `openspec/specs/plugin-framework/spec.md`) shipped a unified
`Plugin` protocol, a `PluginType` enum, and a `quarry.plugins` entry-point loader. `lifecycle-hooks`
used that scaffolding to build the *reaction* half of "domain plugins" — hooks that fire on a scan
event. `PluginType.CONTEXT_INJECTOR` exists in `src/quarry_plugins/base.py` but nothing implements
or loads it: no protocol, no budget/assembly helpers, no hunt-prompt wiring.

Three pieces of existing machinery this design reuses directly:

- **`ArchitectureDoc.repo_type`** (`schemas.py:933`, `"web_service" | "cli" | "fuzzing" | "mixed"`),
  inferred by `recon_synthesis.py:_infer_repo_type` from entry-point kinds. Available inside
  **`emit_agent_tasks`** (`emit_agent_tasks.py:74`, `arch_doc = ArchitectureDoc.model_validate_json(...)`),
  which is also where every hunt `AgentTask` is built (lines ~95-108) — the natural point to
  compute domain context, since it already has `repo_type` and iterates every `(vuln_class, scope)`
  pair.
- **`hunt_impl`**'s `variables` dict (`hunt.py:155-164`) — the sole place hunt-prompt Jinja
  variables are assembled from an `AgentTask`. Every hunt template (`prompts/hunt/hunt.1.0.0.j2` +
  17 per-class templates) uses `StrictUndefined`, so a new variable needs a default everywhere.
- **`ScanProfile.plugins_active: list[str]`** (`schemas.py:315`) — already exists, already flows
  end-to-end into `ScanManifest` for provenance, but today it's dead: `local_scan_profile()` has
  no parameter to set it, and nothing resolves it from `quarry.toml`. Every real scan gets `[]`.

## Goals / Non-Goals

**Goals:**
- A `ContextInjectorPlugin` protocol + budget/assembly helpers, following the exact discovery
  pattern already proven for tools/sinks/hooks (entry-points, fail-soft loading).
- Real hunt-prompt wiring: a matching plugin's text actually appears in the rendered prompt sent
  to the model; a non-matching plugin contributes nothing (the portability invariant).
- Make `plugins_active` real: resolve it from `quarry.toml` (mirroring the `[integrations.*]`
  pattern from `lifecycle-hooks`), and use it as the activation allowlist for context injectors.
- Two placeholder-only OSS reference stubs (`multitenant_isolation`, `template_injection`).
- Benchmark scans continue to trigger zero injector output — code-enforced, not conventional.

**Non-Goals:**
- Real (non-placeholder) domain content — that lives in a private repo, out of scope here.
- The four additional OSS example stubs (auth/session, SSRF allowlist, insecure deserialization,
  mass assignment) from the original week-15-optional roadmap — a natural follow-on once this
  lands, not required to "finish" the core capability.
- `TICKETING` / `METRICS` / `MODEL_PROVIDER` plugin types — still placeholders, untouched.
- Using `plugins_active` as a general-purpose plugin allowlist for tools/sinks/hooks too — scoped
  to context injectors only for this change; generalizing it is a separate decision.

## Decisions

**Injection happens in `emit_agent_tasks`, not via the lifecycle-event stream.** The
`lifecycle-hooks` dispatch mechanism reacts to *events after the fact* (a finding was validated);
context injection needs to shape the *prompt before the model ever runs*. These are genuinely
different integration points sharing only the `Plugin`/discovery layer. `emit_agent_tasks` is
already where `repo_type` and every `AgentTask` meet, so computing `domain_context` there and
stamping it onto the task lets it ride through Temporal to `hunt_impl` with zero new activity
arguments.

**`AgentTask.domain_context: str = ""`, parallel to the existing `recon_notes` field.** Same
shape, same purpose (carry precomputed text from task-emission time to hunt-prompt time), no new
persistence concept. Threaded into `hunt_impl`'s `variables` dict as `"domain_context"`, rendered
in a `<!-- QUARRY:PART:developer -->` block via `{{ domain_context | default("") }}` — the
`default` is mandatory given `StrictUndefined`.

**Domain context is first-party instruction, never wrapped in `<target_content>`.** It is
operator/plugin-authored config, not target-controlled data — same trust level as the scan
profile itself. Putting it in the evidence part or scrubbing it would misrepresent its trust
level and could get it filtered by mechanisms meant for untrusted content.

**Budget enforced in code, not as a prompt instruction.** `enforce_context_budget(text,
max_tokens=500) -> tuple[str, bool]` uses a deterministic char-count heuristic (~4 chars/token),
truncates at the boundary with a trailing note, and returns whether truncation occurred (logged,
never silent). Alternative rejected: telling the model "keep this under 500 tokens" in the prompt
itself — unenforceable and not testable.

**Priority-ascending, labeled concatenation.** `assemble_domain_context(plugins, attack_class,
task, repo_type) -> tuple[str, list[str]]` filters to plugins whose `attack_classes` contains the
class and whose `inject_context()` returns non-`None`, sorts ascending by `priority`, applies the
budget per block, concatenates as `## Domain context: {name}`, and returns the assembled text
plus contributing plugin names (for provenance).

**`plugins_active` becomes a real, quarry.toml-sourced allowlist — empty by default.** Add
`plugins_active: list[str] = []` to `ScanDefaultsConfig` (`panel_config.py`), resolved into
`ScanProfile.plugins_active` at the API layer exactly like `resolve_integration_configs` was for
`lifecycle-hooks` (same call site, `quarry_server/routers/scans.py`). `emit_agent_tasks` only
calls `inject_context` on plugins whose `name` appears in `plugins_active` — so an unconfigured
scan gets zero injector output, matching `plugin-development.md`'s stated invariant ("plugins are
disabled by default unless... explicitly enabled by a scan profile"). Benchmark scans force
`plugins_active = []` explicitly (defense in depth against a global quarry.toml opt-in) —
reusing the `benchmark: bool` flag already threaded end-to-end by `lifecycle-hooks`.

**Alternative rejected:** run every discovered `CONTEXT_INJECTOR` plugin unconditionally, relying
solely on each plugin's own `repo_type`/`attack_class` match to stay silent on the wrong target.
Rejected — it makes `plugins_active` permanently dead code (nothing ever reads it), and it means
installing a third-party context-injector package silently activates it repo-wide with no
explicit opt-in, contradicting the documented disabled-by-default invariant.

**Portability is enforced by convention + a golden test, not by a type-level guarantee.** Same
approach `lifecycle-hooks` used for its scrub-before-egress invariant: `multitenant_isolation`
and `template_injection` are unit-tested against a repo whose `repo_type` doesn't match, asserting
`None`. There's no way to make "returns `None` off-target" a compile-time guarantee for
third-party plugins; the test documents and locks the *reference* implementations' behavior.

## Risks / Trade-offs

- **[Risk] Touching 18 Jinja templates is mechanical but wide-blast-radius.** → Mitigation: the
  change is additive and defaulted (`{{ domain_context | default("") }}` renders empty today for
  every scan, since `plugins_active` defaults to `[]`) — existing golden-fixture prompt hashes for
  scans with no active injectors are unaffected. Verify with the existing `task prompt-lint`
  invariant (ADR-019) plus a round-trip render test per template.
- **[Risk] A misconfigured plugin returns unbounded text, bloating every hunt prompt for a scan.**
  → Mitigation: budget enforcement is unconditional and per-block, applied before concatenation,
  regardless of what the plugin returns.
- **[Trade-off] `plugins_active` is scoped to context injectors only in this change**, even though
  the field's original intent (per `adr-015`/`schemas.md`) was likely broader. Accepted — avoids
  entangling this change with a decision about tool/sink/hook activation policy that isn't needed
  yet and has no shipped use case pressing for it.
- **[Risk] Real domain content accidentally lands in an OSS stub during future edits.** →
  Mitigation: the golden portability test is the guardrail (asserts placeholder-only content
  never activates off-target); the private-repo boundary itself is a `week-15-optional` follow-on,
  not solved here.

## Migration Plan

1. Land the protocol + budget/assembly helpers (`quarry_plugins/base.py`,
   `quarry_plugins/budget.py`) with unit tests — no wiring yet, fully inert.
2. Land the `AgentTask.domain_context` field + `plugins_active` quarry.toml plumbing — still
   inert (nothing calls the assembly helper yet), verified by schema/config tests only.
3. Wire `emit_agent_tasks` to compute and stamp `domain_context`, gated by the (still-empty-by-
   default) `plugins_active` allowlist — existing scans see zero behavior change.
4. Thread `domain_context` into `hunt_impl`'s variables and add the Jinja default across all 18
   templates — still zero visible change for any scan without an explicit `plugins_active` entry.
5. Ship the two OSS stubs + entry-point registration + portability tests — now, and only for a
   scan that explicitly configures `plugins_active`, does anything actually render.
6. Benchmark-safety test: assert a benchmark scan's rendered hunt prompts never contain a
   `## Domain context:` block even if `plugins_active` were (incorrectly) non-empty.
7. Rollback: every layer is additive and gated by an empty-by-default allowlist; reverting step 3
   alone fully disables output while leaving the protocol/helpers in place.

## Open Questions

1. Should `plugins_active` be able to activate context injectors per-scan (via the API/CLI, like
   `vuln_classes`) in addition to via `quarry.toml`, or is a global config-only activation
   sufficient for now? Leaning config-only for this change — confirm before task 3.
2. Where should the `## Domain context:` label live relative to `recon_notes` in the developer
   part of the templates — before or after? Leaning after (domain context supplements, doesn't
   precede, the concrete recon leads) — low-stakes, confirm during template edits.
