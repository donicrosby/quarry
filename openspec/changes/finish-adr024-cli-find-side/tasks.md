## 1. BuildCommand population (C1)

- [ ] 1.1 Write failing tests that recon synthesis on a Rust target (Cargo.toml) populates `BuildCommand` with `cargo build --release`, and on a Python target populates a run command; verify they fail (Red)
- [ ] 1.2 Implement build-system detection in `recon_synthesis.py` (Cargo, npm, pyproject/setup.py, Makefile, go.mod, CMake) replacing the hardcoded `build_commands=[]`; verify 1.1 passes (Green)
- [ ] 1.3 Write a failing test that an unknown build system yields an empty list with a recorded skip reason (not a crash); implement; verify
- [ ] 1.4 Refactor detector table for clarity; `ruff check`, `ruff format`, `pyright`, full `pytest -x -q`

## 2. EntryPoint invocation metadata (C2)

- [ ] 2.1 Write failing tests for `EntryPoint.invocation: list[str]` and `EntryPoint.attacker_controlled_input` enum (`args|stdin|env|config_file|none`), including persistence round-trip; verify they fail (Red)
- [ ] 2.2 Add the fields to `src/quarry/schemas.py` with typed defaults; verify 2.1 passes (Green)
- [ ] 2.3 Write failing tests that recon populates invocation metadata for `examples/vulnerable-cli` (`invocation` includes the built binary path, `attacker_controlled_input == "args"`); verify fail
- [ ] 2.4 Wire recon synthesis to populate the new fields for CLI targets; verify 2.3 passes
- [ ] 2.5 Update ground-truth fixture alignment: `cli_invocation` in `tests/golden/ground_truth/` maps onto the new schema fields; verify golden tests pass

## 3. Verify end-to-end + land

- [ ] 3.1 Integration test: recon on `examples/vulnerable-cli` produces ArchitectureDoc whose BuildCommand + EntryPoint.invocation suffice for the prove stage to build and invoke from source (no manual commands)
- [ ] 3.2 `uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest -x -q` all green
- [ ] 3.3 `openspec validate finish-adr024-cli-find-side --strict`, commit, push, open PR
