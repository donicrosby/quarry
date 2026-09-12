# Quarry Architecture

Quarry is a local-first agentic vulnerability research harness for source-aware web and API testing.

## Data flow

```
CLI/TUI → QuarryClient (httpx) → FastAPI server (quarry_server)
       → Temporal workflow (quarry_workflows)
       → Activities (quarry_activities)
       ↕
       ToolRunner (quarry_tools) → Built-in tools (read_file, list_dir, grep, search_code,
                                   call-graph backends, opengrep, treesitter, sandbox/http)
       ModelClient (quarry_models) → run_agent_loop → guards
       ↕
       SQLite (quarry_persistence) / Filesystem artifacts (quarry_artifacts)
```

## What is real

- **Recon agent** — `ReconWorkflow` runs a multi-turn agent loop over any repository to produce an `ArchitectureDoc` (primary language, subsystems, entry points, trust boundaries, build commands). Language detection is agent reasoning over generic tool output — no language-specific Python. Recon synthesis also renders an attack-surface summary into `reports/<scan_id>-architecture.md`.
- **Agent harness** — `run_agent_loop` in `quarry_models/loop.py` with per-iteration budget + iteration caps, instruction/evidence separation (`<target_content>` tags), and a guard set (leaked-secret, schema-mismatch).
- **Tool registry** — `quarry_tools`: `ToolRunner` enforces repo-root path restriction and per-role allowlists; built-in tools: `read_file`, `list_dir`, `grep` (ripgrep), `search_code` (ast-grep), plus extension tools `opengrep`, `treesitter_query`, Python/SCIP call-graph backends, `sandbox_exec`, and `http` (dynamic validation), loadable via the `quarry.plugins` entry-points group.
- **quarry.toml config** — `load_quarry_config`, `resolve_panel`, `resolve_focus` in `quarry/panel_config.py`. `--focus ssrf,xss` on the CLI limits the scan to specific classes; unknown tokens fail fast.
- **Scope exclusions** — `ScopeExclusion` + `build_exclusion_block` injects an out-of-scope block into the instruction envelope; target-controlled content cannot remove it.
- **Hunt** — per-vuln-class agentic hunters (18 classes, per-class templates in `prompts/hunt/`); each candidate gets a fingerprint + root-cause key. Unconstrained exploratory hunts (`prompts/task/explore.1.0.0.j2`) are injected into gapfill per `scan_defaults.exploratory_injection_fraction` (default 0.3, cap 0.5), targeting ledger gap paths with no threat-model context.
- **Knowledge base** — the `kb-recon` activity builds a per-scan KB root index (`KBRootIndex` → component entities, vuln-class notes, dependency graph); the `kb_context` injector resolves references into rendered hunt/gapfill/validate prompt context with inline fallback when absent.
- **Validation** — adversarial: a negative-constraint checklist refuter (`checklist.py`, `prompts/validate/refute.1.0.0.j2`) assumes false-positive-by-default and requires the checklist to discharge that stance from code; optional tiered debater ensemble argues to refute from an independent model, producing ordinal credibility (refuted / contested / unrefuted). Dynamic HTTP checks against a live target produce safe local proof artifacts.
- **Calibration** — post-validation severity calibration stage (`calibrate.py`) re-scores each validated finding.
- **Proof & tracing** — PROVE stage generates safe local exploit chains (capped attempts); TRACER computes reachability verdicts + severity re-ranking via call graphs.
- **Dedup** — findings dedup by fingerprint / root-cause key.
- **Provenance** — `ScanManifest`, `FindingProvenance`, model/tool invocation records, retention-gated seed-prompt artifacts (see `docs/prompt-registry.md`).
- **Resume** — workflows checkpoint completed stages; resume skips already-completed stages.
- **Replay** — `POST /scans/{id}/replay` re-renders the Markdown report from stored findings and provenance without new scan or model calls.
- **Dry-run integrations** — Jira and Slack sinks write payload artifacts; no external calls.
- **Coverage ledger** — production-file accounting: every manifest entry is covered, intentionally excluded (tests / vendored / generated / build-config-data, each with a recorded reason), or an honest gap; scope exclusions are recorded, not dropped.

## Deferred

- Kubernetes deployment (see `docs/kubernetes-scale-plan.md`).
- Postgres migration.
- Signed provenance / SBOM.
