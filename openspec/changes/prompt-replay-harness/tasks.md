# Tasks: prompt-replay-harness

## 1. Input resolvers (foundation)

- [ ] 1.1 Write failing tests for a `quarry_replay` resolver that loads a candidate finding + panel JSON + repo path for `replay validate` from a prior scan's DB (mirror `scripts/replay_validate.py`'s `_load_candidate` / `_resolve_validate_panel_json`); verify fail (Red)
- [ ] 1.2 Implement `src/quarry_replay/resolvers.py` with the validate resolver; verify 1.1 passes (Green)
- [ ] 1.3 Write failing tests for fail-loud behavior: resolver raises a named error when the scan predates a required input (no KB key, no candidates for class); verify fail
- [ ] 1.4 Implement fail-loud resolution (explicit errors, no fabricated fallbacks); verify 1.3 passes
- [ ] 1.5 Write failing tests for hunt/gapfill/prove/trace/recon resolvers reconstructing each activity's call args from persisted state (agent tasks, KB artifacts, findings, target endpoint); verify fail
- [ ] 1.6 Implement the remaining resolvers; verify 1.5 passes

## 2. Replay runner + provenance tagging

- [ ] 2.1 Write failing tests for a `quarry_replay.runner` that invokes a given activity function directly with resolved args under a resolved panel, and records invocations with a replay marker (not a scan marker); verify fail
- [ ] 2.2 Implement the runner (direct activity call, model routing via `load_quarry_config`+`resolve_panel`, replay-tagged invocation recording); verify 2.1 passes
- [ ] 2.3 Write failing tests that replay does NOT mutate scan state: scan status/findings/events unchanged after a replay; verify fail
- [ ] 2.4 Implement read-only enforcement (no scan-record writes in the replay path); verify 2.3 passes
- [ ] 2.5 Write failing tests for `--mock` mode: mock panel selected explicitly, no network call, output header labels result as mock; verify fail
- [ ] 2.6 Implement `--mock` selection + output labeling; verify 2.5 passes

## 3. CLI

- [ ] 3.1 Write failing tests for `quarry replay validate|hunt|gapfill|prove|trace|recon` CLI wiring (arg parsing → resolver → runner → printed result); verify fail
- [ ] 3.2 Implement the `replay` command group in `src/quarry_cli/`; verify 3.1 passes
- [ ] 3.3 Retire or shim `scripts/replay_validate.py` to call the new `replay validate` path (keep behavior identical); update its docstring
- [ ] 3.4 Verify `replay validate` reproduces `scripts/replay_validate.py`'s output shape against a real prior scan DB (manual check, no new spend beyond one cheap replay)

## 4. Mock-panel golden tests + gate

- [ ] 4.1 Write a mock-panel golden replay test per stage: input resolves, activity runs, result structurally valid, no network/Temporal; run all
- [ ] 4.2 Run the full unit suite (`uv run pytest tests/unit -q -n 2`) and confirm no regressions
- [ ] 4.3 Run lint + typecheck (`uv run ruff check . && uv run pyright`) clean

## 5. Docs

- [ ] 5.1 Add a "Prompt iteration with replay" section to the README or docs describing `quarry replay <stage>` usage, mock vs real modes, and the read-only/replay-tagged guarantees
- [ ] 5.2 `openspec validate prompt-replay-harness --strict` clean; tick all boxes in the landing commit
