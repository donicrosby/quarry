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
