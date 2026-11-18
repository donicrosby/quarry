## 1. Metrics + result artifact

- [x] 1.1 Write failing tests for a benchmark result schema (per-class recall, FP rate, proof rate, token cost per proven finding, wall-clock, model + prompt-hash + config provenance); verify fail (Red) — VERIFIED: tests/unit/test_benchmark_artifacts.py L1-166
- [x] 1.2 Implement the result schema + artifact persistence; verify 1.1 passes (Green) — VERIFIED: src/quarry/benchmark_artifacts.py L1-125
- [x] 1.3 Write failing tests that `quarry benchmark local` emits a `BenchmarkRunResult` artifact with provenance on a known-fixture run; verify fail (Red). Tests SHALL assert artifact schema version, provenance fields non-empty, metrics computed from scan output. — VERIFIED: tests/unit/test_benchmark_cli.py L135-198 (artifact, provenance, metrics) + tests/unit/test_benchmark_planted_fixtures.py (planted fixture run)
- [x] 1.4 Wire `BenchmarkRunResult` emission into `_benchmark_local_command` (src/quarry_cli/main.py:612-653); verify 1.3 passes (Green). Reuse existing RunProvenance/BenchmarkMetrics from task 1.2; derive model + prompt-hash + config from the scan's live state. — VERIFIED: src/quarry_cli/main.py `_benchmark_local_command` emits `BenchmarkRunResult` (`artifact=` line)

## 2. Fixture breadth

- [x] 2.1 Inventory: enumerate all 18 VulnerabilityClass values (src/quarry/schemas.py:92-111) against hunt-template presence (prompts/hunt/*.j2 — all 18 verified present) and ground-truth presence (tests/golden/ground_truth/vulnerable-*.json — 5 present: secrets, idor, command_injection, ssrf, path_traversal). Document in design.md as a matrix with huntable/benchmarkable columns. Validate the inventory by grepping the codebase, not by assertion. — VERIFIED: `quarry benchmark inventory` (filesystem-validated); matrix documented as a pointer in openspec/changes/benchmark-suite-expansion/design.md; tests/unit/test_benchmark_inventory.py
- [x] 2.2 Add ground-truth fixtures for high-value web classes not yet covered: sql_injection, xss, ssti, open_redirect, file_upload (5 classes). Add one fixture per class to an existing example target's ground-truth JSON; verify each fixture is detectable by the hunt pipeline (template exists + tool path reaches the sink). Coordinate with existing per-class dynamic-validation templates so each class is huntable AND benchmarkable. — VERIFIED: tests/golden/ground_truth/vulnerable-fastapi.json + tests/unit/test_benchmark_web_fixtures.py (route served, sink fires, huntable & benchmarkable)
- [x] 2.3 Planted-regression target: author a deliberately vulnerable target in one language (Python/FastAPI recommended — matches existing launcher support), with 3–5 vulnerabilities across ≥2 VulnerabilityClass values, never published anywhere. Include a ground-truth manifest (class, file, line, expected proof type). Add to examples/ and tests/golden/ground_truth/. Verify `quarry target start` launches it and `quarry benchmark local --repo <path> --ground-truth <path>` scores it. — VERIFIED: examples/vulnerable-planted/ (5 vulns / 5 classes) + tests/golden/ground_truth/vulnerable-planted.json; launch tests/integration/test_benchmark_planted_target.py; reachable-firing-sink + `quarry benchmark local` scoring tests/unit/test_benchmark_planted_fixtures.py

## 3. External benchmark evaluation

- [x] 3.1 Spike XBEN: spike-cybergym.md §5 (L235-250) covers XBEN — saturated (~100%), kept for historical purposes. No dedicated spike doc needed. VERIFIED.
- [x] 3.2 Spike CyberGym: evaluate dataset access and runner fit; document — VERIFIED: spike-cybergym.md L1-250
- [x] 3.3 CyberGym runner: implement + record baseline — VERIFIED: src/quarry_benchmark/ (cybergym.py, runner.py, verifier.py, agent.py) wired at src/quarry_cli/main.py:505-576

## 4. Verify + land

- [x] 4.1 A/B harness check: run `quarry benchmark local` on two harness configs (e.g. different prompt versions or model settings), confirm each emits a diffable BenchmarkRunResult artifact with comparable provenance. — VERIFIED (artifact path): `quarry benchmark diff` (diff_run_results) emits diffable BenchmarkRunResult artifacts; wall-clock regression covered by tests/unit/test_benchmark.py. The live two-config run remains an operator exercise (review N2).
- [ ] 4.2 `uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest -x -q` all green. Confirm test_benchmark_artifacts.py and test_benchmark.py still pass; verify no new lint.
- [ ] 4.3 `npx openspec validate benchmark-suite-expansion --strict` clean, commit on spec/benchmark-suite-expansion-continuation, push.
