## Why

"To improve a system, you have to measure it" (Microsoft MDASH, iterating
against CyberGym's 1,507 real-world vulnerabilities). Quarry's `quarry benchmark
local` exists but covers only 5 ground-truth classes
(`tests/golden/ground_truth/`), which is not enough signal to know whether a
harness change improves or regresses outcomes.

The goal is a benchmark suite that can (a) score Quarry against external
benchmarks — CyberGym and Shannon's XBEN targets — for comparability, and (b)
A/B harness changes locally with consistent metrics.

## What Changes

- **Expand local benchmark breadth.** Ground-truth fixtures and vulnerable-*
  targets covering every `VulnerabilityClass`, web and CLI. Extends
  `benchmarking-and-evaluation` and `example-targets-and-fixtures`.
- **Planted-regression target.** A target with N known vulnerabilities never
  published anywhere (the analog of Microsoft's StorageDrive interview driver),
  used to detect harness regressions without training-data contamination.
- **Standard metrics per run.** Recall per class, false-positive rate, proof
  rate (found → proven), token cost per proven finding, wall-clock. Results
  stored as artifacts with provenance (model, prompt hashes, config) so runs
  are comparable across harness changes.
- **External benchmark evaluation.** Evaluate CyberGym and XBEN for adoption;
  pick at least one and wire a runner. (CyberGym is the MDASH benchmark; XBEN
  is what Shannon publishes against, giving direct comparability.)

## Reconciliation notes (2026-11-15, ~45 merges since original 2026-09-10 ticket)

This change already had 4/13 tasks done (1.1, 1.2, 3.2, 3.3) when the board
went live. Refresh against main @ b284af7 confirms:

- **Tasks 1.1/1.2 (VERIFIED done).** `src/quarry/benchmark_artifacts.py`
  (BenchmarkMetrics, BenchmarkRunResult, RunProvenance, TaskOutcome) + tests in
  `tests/unit/test_benchmark_artifacts.py`.
- **Tasks 3.2/3.3 (VERIFIED done).** spike-cybergym.md + `src/quarry_benchmark/`
  package (cybergym.py, runner.py, verifier.py, agent.py) wired into
  `quarry benchmark cybergym` at src/quarry_cli/main.py:505-576.
- **Hunt template gap resolved since original ticket.** All 18
  VulnerabilityClass values now have hunt templates (verified: 20 templates at
  prompts/hunt/*.j2, all 18 enum members represented). The original spec's
  "xxe, file_upload, csrf SHALL be added" mandate is satisfied on main. Note:
  `csrf` template exists but `csrf` is NOT in the VulnerabilityClass enum
  (src/quarry/schemas.py:92-111) — reconciliation finding, out of scope.
- **Local benchmark artifact gap.** `quarry benchmark local` still uses the
  lightweight `compare()` → `BenchmarkResult` path (src/quarry/benchmark.py:63)
  and does NOT emit a `BenchmarkRunResult` artifact with provenance. Tasks
  1.3/1.4 remain open.
- **Fixture breadth.** Ground truth covers 5 of 18 classes (secrets, idor,
  command_injection, ssrf, path_traversal — verified at
  tests/golden/ground_truth/vulnerable-*.json). Tasks 2.1/2.2 rescoped: not
  all 18 classes need fixtures simultaneously; differentiated into
  huntable-from-template vs benchmarkable (has ground truth).
- **XBEN spike (task 3.1).** spike-cybergym.md §5 (lines 235-250) covers XBEN:
  saturated (~100%), kept for historical purposes. Consolidated here; no
  dedicated XBEN spike doc needed.
- **Planted-regression target (task 2.3).** No planted vulnerable target exists
  (verified: grep for 'planted' outside spec docs matches only the incidental
  "no planted secrets" docstring at tests/integration/test_e2e_temporal.py:135
  describing a clean fixture). Scoped to one modest target (3–5 vulns, one
  language).

## Impact

- Affected specs: `benchmarking-and-evaluation`, `example-targets-and-fixtures`
- Affected code: `src/quarry_cli/main.py` (`quarry benchmark`), benchmark
  runner/scoring, new ground-truth fixtures and example targets, new benchmark
  result artifact schema
- Unblocks: honest A/B of every other harness change on the board; the
  agentic-SAST spike (t_ab68b0aa) which requires measurement infrastructure
- Board tickets: t_e709f5db

## Non-goals

- No claim of leaderboard submission or publication.
- No CI gating on absolute scores yet (metrics first, thresholds later).
- External benchmark *adoption* decision is an output of this change, not a
  precondition.
- No fix for `csrf` template existing outside `VulnerabilityClass` enum
  (separate spec debt).
