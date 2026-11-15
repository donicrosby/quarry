# Change: dependency-manifest-scanner

## Why

Quarry recon reads dependency manifests (package.json, Cargo.toml, pyproject.toml,
requirements.txt, go.mod) for language detection and KB recon builds code-side import
graphs, but neither examines the manifest contents for supply-chain risk. Unpinned
versions, git-sourced dependencies, typosquat package names, npm install scripts, and
curl-pipe-shell patterns are all detectable statically from the same manifest files the
orchestrator already opens — yet no activity currently flags them. A deterministic
pre-recon scan closes this gap without adding model cost or latency.

## What Changes

- **New `SUPPLY_CHAIN` vulnerability class** added to `VulnerabilityClass` enum.
- **New `dependency-risk-scanner` activity** — deterministic (no model calls), runs
  pre-recon, parses five manifest formats and emits one `CandidateFinding` per risk.
- **Five risk checks**: unpinned version specifiers (severity HIGH), git/URL-sourced
  dependencies (severity HIGH), typosquat name patterns against a configurable list
  (severity MEDIUM), npm pre/postinstall script presence (severity MEDIUM), and
  curl|sh / wget|sh patterns in npm scripts (severity CRITICAL).
- **Manifest formats**: requirements.txt, pyproject.toml, package.json, Cargo.toml,
  go.mod — the five ecosystems the original slice-3 ticket targets.

## Impact

- **Specs**: `dependency-manifest-scanning` (new capability, 8 ADDED requirements).
  No MODIFIED deltas elsewhere: the scanner dispatches inside the existing stage
  sequence, so `scan-orchestration`'s canonical stage order (`COMPLETED_STAGE_ORDER`)
  is untouched.
- **Code**: `src/quarry/schemas.py` (new `SUPPLY_CHAIN` enum member),
  `src/quarry_activities/dependency_risk.py` (new activity file), activity registration
  via existing `discover_activities()` auto-discovery (VERIFIED at
  b284af7:src/quarry_activities/registry.py:29-41).
- **Config**: `quarry.config` grows a `typosquat_patterns: list[str]` key
  (default empty — the check is a no-op until configured).
- **Threat model**: The activity reads manifest files already present in the cloned
  repo; it writes no files, makes no network calls, and invokes no model. No new trust
  boundary. Findings are advisory (candidate status) and flow through the normal
  validate/dedup pipeline.
- **Non-goals**: Recursive multi-repo dependency tree scanning (single-repo only);
  lockfile parsing (npm-shrinkwrap.json, Cargo.lock, Pipfile.lock — lockfiles are
  read-only records of resolved versions, not human-authored risk surfaces); Gradle/Maven
  dependency resolution (the scanner parses the manifests the original ticket names);
  automated remediation or PR generation (findings are informational).

## Reconcile notes (2026-09-10 original vs b284af7 main)

- **Kept**: All five manifest formats from the original ticket (requirements.txt,
  pyproject.toml, package.json, Cargo.toml, go.mod). Deterministic no-model execution.
  Unpinned version, git+https, pre/postinstall, and curl|sh checks. CandidateFinding
  emission with risk-graded severity.
- **Dropped**: Hardcoded typosquat examples (python-dateutil vs dateutil) — replaced
  by a configurable pattern list so operators can maintain their own database without
  code changes. The scanner does not recurse into transitive dependencies (the
  original ticket was scoped to manifest reading, not dependency-tree resolution).
- **Rescoped**: The severity mapping is explicit per check type (CRITICAL for
  curl|sh, HIGH for unpinned/git-dep, MEDIUM for typosquat/install-scripts) rather
  than a single "severity based on risk" heuristic — this makes the scanner's output
  predictable and testable.
- **Alignment with existing code**: `recon_orchestrator.py` (VERIFIED at
  b284af7:src/quarry_activities/recon_orchestrator.py:19-32) already maps manifest
  filenames to languages, and `kb_recon.py` (VERIFIED at
  b284af7:src/quarry_activities/kb_recon.py:123-150) derives code-side dependency
  graphs. The scanner complements both: it reads the SAME manifests for a DIFFERENT
  purpose (risk assessment vs language detection vs import analysis) without
  duplicating their logic.