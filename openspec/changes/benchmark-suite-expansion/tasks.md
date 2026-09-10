## 1. Metrics + result artifact

- [ ] 1.1 Write failing tests for a benchmark result schema (per-class recall, FP rate, proof rate, token cost per proven finding, wall-clock, model + prompt-hash + config provenance); verify fail (Red)
- [ ] 1.2 Implement the result schema + artifact persistence; verify 1.1 passes (Green)
- [ ] 1.3 Write failing tests that `quarry benchmark local` emits the result artifact with correct metric computation on a known-fixture run; verify fail
- [ ] 1.4 Wire metric computation into the benchmark runner; verify 1.3 passes

## 2. Fixture breadth

- [ ] 2.1 Inventory: matrix of `VulnerabilityClass` × (web|cli) × present/absent ground truth; identify gaps
- [ ] 2.2 Add ground-truth fixtures + example-target vulns to cover every huntable class (coordinate with per-class-dynamic-validation templates so each class is huntable AND benchmarkable)
- [ ] 2.3 Planted-regression target: author a target with known vulns not published anywhere; ground-truth manifest with locations and expected proof type

## 3. External benchmark evaluation

- [ ] 3.1 Spike XBEN: enumerate targets, evaluate runner fit (Shannon publishes against it — direct comparability); document per-target bring-up requirements against the generalized target launcher
- [ ] 3.2 Spike CyberGym: evaluate dataset access and runner fit; document
- [ ] 3.3 Pick one external benchmark, implement a runner, record a baseline score with provenance

## 4. Verify + land

- [ ] 4.1 A/B harness check: run benchmark on two configs, confirm results are stored comparably and diffable
- [ ] 4.2 `uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest -x -q` all green
- [ ] 4.3 `openspec validate benchmark-suite-expansion --strict`, commit, push, open PR
