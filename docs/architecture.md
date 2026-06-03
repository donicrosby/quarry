# Quarry Architecture

Quarry is a local-first agentic vulnerability research harness for source-aware web and API testing.

## Data flow

```
CLI/TUI → QuarryClient (httpx) → FastAPI server (quarry_server)
       → Temporal workflow (quarry_workflows)
       → Activities (quarry_activities)
       ↕
       ToolRunner (quarry_tools) → Built-in tools (read_file, list_dir, grep, search_code)
       ModelClient (quarry_models) → run_agent_loop → guards
       ↕
       SQLite (quarry_persistence) / Filesystem artifacts (quarry_artifacts)
```

## What is real

- **Recon agent** — `ReconWorkflow` runs a multi-turn agent loop over any repository to produce an `ArchitectureDoc` (primary language, subsystems, entry points, trust boundaries, build commands). Language detection is agent reasoning over generic tool output — no language-specific Python.
- **Agent harness** — `run_agent_loop` in `quarry_models/loop.py` with per-iteration budget + iteration caps, instruction/evidence separation (`<target_content>` tags), and a guard set (leaked-secret, schema-mismatch).
- **Tool registry** — `quarry_tools`: `ToolRunner` enforces repo-root path restriction and per-role allowlists; built-in tools: `read_file`, `list_dir`, `grep` (ripgrep), `search_code` (ast-grep).
- **quarry.toml config** — `load_quarry_config`, `resolve_panel`, `resolve_focus` in `quarry/panel_config.py`. `--focus ssrf,xss` on the CLI limits the scan to specific classes; unknown tokens fail fast.
- **Scope exclusions** — `ScopeExclusion` + `build_exclusion_block` injects an out-of-scope block into the instruction envelope; target-controlled content cannot remove it.
- **Attack-surface mapping** — FastAPI route extraction via Python `ast`.
- **Secrets scanning** — regex-based scanner in `quarry_plugins/vuln_classes/secrets.py`.
- **IDOR scanning** — two-user dynamic check in `quarry_plugins/vuln_classes/idor.py`.
- **Command-injection scanning** — source-to-sink detection in `quarry_plugins/vuln_classes/command_injection.py`.
- **Validation** — dynamic HTTP check against live target; produces safe local proof artifacts.
- **Provenance** — `ScanManifest`, `FindingProvenance`, model/tool invocation records.
- **Resume** — workflows checkpoint completed stages; resume skips already-completed stages.
- **Replay** — `POST /scans/{id}/replay` re-renders the Markdown report from stored findings and provenance without new scan or model calls.
- **Dry-run integrations** — Jira and Slack sinks write payload artifacts; no external calls.
- **Coverage ledger** — records which attack surface items were scanned vs. skipped and why.

## Deferred

- Real model calls in the scan path (uses `MockModelClient`; provider wiring is later milestones).
- Automatic target launching.
- Kubernetes deployment (see `docs/kubernetes-scale-plan.md`).
- Postgres migration.
- Signed provenance / SBOM.
- Extension tools (`opengrep`, `treesitter_query`) and `quarry.tools` entry-points loader.
