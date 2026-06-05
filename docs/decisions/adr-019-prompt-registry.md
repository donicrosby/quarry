# ADR 019: Prompt registry and Jinja rendering

## Status

Accepted

## Context

As the agentic pipeline adds more stages (hunt, validate, gapfill, prove, trace), the
number of prompt strings in Python grows.  Inline strings are hard to diff, version,
audit, and test in isolation.  They cannot carry semver versions, they have no sha256
fingerprint for provenance, and they are a SSTI risk if target-controlled content is
ever inadvertently compiled as a template.

The week-12 hunt prompt already lived entirely in `src/quarry_models/prompts/hunt.py`;
the recon subsystem prompt was an inline string in `recon_subsystem.py`.  This ADR
establishes the canonical design before week 13 adds more prompts.

## Decision

### 1. Invariant: no prompt text in Python

Every prompt — system role text, developer instructions, output schema note — lives in
a versioned Jinja template under `prompts/`.  Python files contain **no** prompt strings.
A CI lint guard (`task prompt-lint`) enforces this.

### 2. `prompts/` layout

```
prompts/
  _envelope/
    system.j2          # System identity macro
    developer.j2       # Developer instructions + scope enforcement
    evidence.j2        # <target_content> fence — only place it appears
    output_schema.j2   # Output schema instructions
  hunt/
    hunt.1.0.0.j2
  recon/
    subsystem.1.0.0.j2
  validate/
    (week 13)
  ...
```

Templates use `_envelope/` macros via Jinja `{% import %}` for structural consistency.

### 3. Semver semantics for prompt templates

| Bump | When |
|------|------|
| PATCH | Typo / whitespace / style fix; output distribution unchanged |
| MINOR | New optional variable added; backward-compatible |
| MAJOR | Structural change; existing callers must update |

### 4. `PromptRegistry` + `build_prompt`

`PromptRegistry` loads templates from the `prompts/` directory at scan startup using
`jinja2.sandbox.SandboxedEnvironment` with `StrictUndefined`.  This means:

- Undefined variables raise immediately (fail-fast, not silent empty strings).
- Template code executes in a sandboxed environment — `{{ self.__class__ }}` and similar
  SSTI payloads cannot access Python internals even if they appear in the template body.

**Critical: evidence is data, not a template.**  Evidence strings (file contents, tool
output) are passed to the Jinja context as plain Python strings — they are never compiled
as templates.  The `evidence.j2` macro receives `evidence_chunks: list[str]` and emits
them verbatim inside `<target_content>` fences.  Passing `{{ 7*7 }}` as evidence produces
the literal `{{ 7*7 }}` in the rendered prompt, not `49`.

`build_prompt(registry, role, name, version, variables) -> RenderedPrompt` is the **sole**
chokepoint where model message lists are constructed.  No other code assembles
`list[ModelMessage]` for agent loops.

### 5. Provenance header

`build_prompt` prepends a YAML front-matter block to the rendered output:

```yaml
# QUARRY PROMPT PROVENANCE
template_id: hunt/hunt
template_version: 1.0.0
template_sha256: <hex>
system_hash: <hex>
developer_hash: <hex>
user_hash: <hex>
evidence_hashes: []
```

The `ModelClient` dispatch path strips this header before sending to the provider.
Hashes are stored in `ModelInvocation` regardless of the `MODEL_PROMPT` artifact
retention mode.

### 6. `resolve_prompts()` startup validation

Called alongside `resolve_focus()` before any model call.  Loads each template in the
configured panel, `env.parse()`-validates the Jinja syntax, and fails fast with a clear
error naming the role if a template is missing or has a syntax error.

### 7. CI lint guard

`task prompt-lint` runs `scripts/prompt_lint.py`, which greps `src/**/*.py` for strings
that look like prompt text (multi-line strings containing `<target_content>`,
`You are a`, `## Task`, or known `_SYSTEM_PROMPT`-style patterns).  Exit code 1 with
file and line number on any match.

## Consequences

- All new agent stages (validate, prove, trace) author their prompts in `prompts/`
  from day one.
- `ModelInvocation` gains structured template provenance fields (`prompt_template_id`,
  `prompt_template_version`, `template_sha256`, `system_prompt_hash`, `user_prompt_hash`,
  `evidence_hashes`), replacing the flat `prompt_version` + `prompt_hash` pair.
- `BuiltPrompt` (`src/quarry_models/prompting.py`) is superseded by `RenderedPrompt`
  from `quarry_prompts.build_prompt`; kept as a compatibility alias until all callers
  migrate.
- The `prompts/` directory is part of the installed package (included in the build
  backend's `module-name` list or as package data).
