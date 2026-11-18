# Proposal: fuzzing-harness

## Why

Quarry proves a finding against a live target and sweeps a repo deterministically for
secrets and SSRF sinks, but it cannot find memory-safety crashes in a compiled target.
A CLI binary or fuzz harness built from the target repo is never exercised with hostile
input: there is no mutation engine, no crash capture, no crash dedup, and no candidate
emission from a crash. A binary that segfaults on malformed argument input is invisible
to the hunt stage.

The building blocks already exist and are unused by any fuzzer:

- `EntryPoint.invocation` + `attacker_controlled_input` name how a CLI/binary entry point
  is invoked and which channel is attacker-controlled (schemas.py:1104-1105); `kind`
  already admits `fuzz_harness` (schemas.py:1097).
- `BuildCommand` carries a build recipe with `purpose` `build`/`fuzz`
  (schemas.py:1176-1179).
- The sandbox executes a `SandboxExecSpec` through a `SandboxBackend` with an allowlist,
  rlimits, and a hard timeout (sandbox.py:71-114), returning a `SandboxResult`
  (sandbox.py:50).
- Deterministic candidate-source sweeps (secrets, SSRF) already turn activity payloads
  into `CandidateFinding` objects for the HUNT stage
  (src/quarry_workflows/candidate_sources.py, run_scan.py:1755-1792) — exactly the
  emission channel a fuzz crash needs.

This change adds a deterministic, non-agentic `fuzz` activity that mutates a built
target's attacker-controlled input, runs it in the sandbox, classifies crashes (signal
death or sanitizer output), dedups them by output hash, and emits one `CandidateFinding`
per unique crash.

## What Changes

1. A new `fuzz` activity (deterministic, no model call) that builds the target from its
   `BuildCommand`, then runs the built binary N times in the sandbox with mutated inputs
   derived from the entry point's `attacker_controlled_input` channel (args only in v1).
2. A mutation engine with four strategies — bit flip, byte insert, byte delete, and
   dictionary substitution/insertion — with configurable dictionary tokens defaulting to
   format-string, path-traversal, and shell-metacharacter payloads.
3. A backend-aware crash classifier that decodes negative exit codes AND exit codes >= 128
   as signal deaths (covering tier-1 proc sandbox rlimit kills AND tier-2 ContainerSandbox
   docker 128+N convention), classifies boundary outcomes by decoded signal under the
   sandbox's mandated rlimits (SIGKILL −9/SIGXCPU −24 from RLIMIT_CPU → boundary non-crash;
   SIGABRT −6 from RLIMIT_AS without sanitizer → boundary non-crash; wall-clock 124
   timed_out → boundary non-crash), and detects ASan/UBSan sanitizer signatures in stderr
   (MSan/TSan not addressed in v1). Plain positive non-zero exits are recorded but are not
   crashes.
4. Crash dedup by output hash (normalized stderr + exit code + signal) — one candidate
   per unique crash regardless of how many runs hit it.
5. A single-class-focus dispatch gate: fuzz only runs when the scan's resolved focus
   contains exactly one `VulnerabilityClass`; multi-class or default-ALL focus skips fuzz
   and records the skip. This gives the required `vuln_class` attribution a deterministic
   source without blocking on a `MEMORY_SAFETY` enum addition (separate change).
6. A dedicated `validate-fuzz-candidate` inline validator that promotes valid crash
   candidates and rejects inconsistent ones, mirroring the secrets validation pattern
   (run_scan.py:1755-1792).
7. Emission: each unique crash becomes a `CandidateFinding` with `trigger_input` set to
   the crashing input and crash metadata (hash, signal/sanitizer kind, seed) in `metadata`.
8. Bounded budget: total runs and per-run timeout are capped, and the activity stops (not
   runs unbounded) when the budget is exhausted.

## Reconciliation against the 2026-09-10 ticket (C5)

The ticket predates ~45 merges. Re-read against main @ b284af7, the following were
dropped or adjusted:

- **Dropped — "fuzz vulnerable-cli, find crash" acceptance.** `examples/vulnerable-cli`
  is a memory-safe Rust binary whose intentional vulnerabilities are command injection
  (`--run-cmd`, main.rs:4) and path traversal (`--read-file`, main.rs:5); it never
  segfaults, and neither bug is detectable by a crash oracle. The acceptance is rescoped:
  the run/mutation/capture plumbing is demonstrated against the built `vulnerable-cli`
  binary, and crash classification + dedup + emission are verified against a synthetic
  crash signature (negative/128+N exit code / sanitizer output) rather than a real
  in-tree crash target. A real crash target is a separate fixture change.
- **Dropped — backtrace-based dedup.** `SandboxResult` captures only `exit_code`,
  stdout, stderr, `elapsed_ms`, and `timed_out` (sandbox.py:50-62); the sandbox captures
  no backtrace and `gdb`/`addr2line` are not on `_COMMAND_ALLOWLIST`
  (sandbox.py:95-108). Dedup uses the output hash, which the ticket listed as the
  fallback.
- **Adjusted — "non-zero exit" as a crash class.** A positive non-zero exit includes
  ordinary error paths (e.g. `exit(1)` on unknown subcommands, main.rs:55). Treating
  every non-zero exit as a crash would flood the pipeline with usage-error candidates, so
  only signal death and sanitizer output classify as crashes; a non-zero exit is captured
  but is not a candidate.
- **Adjusted — crash oracle is now backend-aware and signal-based.** The sandbox uses two
  backends with different exit-code conventions (tier-1 proc via `preexec_fn` returns
  negative on rlimit kill; tier-2 ContainerSandbox passes docker 128+N verbatim). The
  classifier decodes both and classifies boundary outcomes by decoded signal under the
  sandbox's mandated rlimits (SIGKILL/SIGXCPU from RLIMIT_CPU, SIGABRT from RLIMIT_AS
  without sanitizer, wall-clock 124 timeout → boundary non-crash; SIGSEGV/SIGBUS,
  SIGABRT+sanitizer → crash).
- **Pinned — `vuln_class` attribution via single-class-focus dispatch gate.** `EntryPoint`
  (schemas.py:1089-1105) has no `class` attribute; `VulnerabilityClass` (schemas.py:92)
  has no `MEMORY_SAFETY` member. Rather than block on a separate enum change, fuzz
  dispatches only when the scan's resolved focus is exactly one class and attributes
  crashes to that class. Multi-class/default focus skips fuzz. A `MEMORY_SAFETY` enum
  addition is a separate change that would unlock multi-class dispatch.
- **ASSUMED — built-binary execution path.** `_COMMAND_ALLOWLIST` (sandbox.py:95-108)
  does not admit arbitrary built binaries; running the built target needs either
  `sh`-mediation or a path-scoped allowlist widening (sandbox.py:94: "Widening is the CLI
  follow-on's job"). The coder must validate the cleanest execution path; it is not
  decided here.
- **ASSUMED — the binary must be built, not shipped.** `examples/vulnerable-cli/.gitignore:1`
  ignores `target/`, so the prebuilt binary is a local build artifact, not a committed
  file. The fuzz activity must produce the binary from `BuildCommand` (per its `purpose`
  `build`), it cannot assume one is present.
- **Unchanged and still real — C1/C2/D1 dependencies.** `BuildCommand` (C1),
  `EntryPoint.invocation` (C2), and the sandbox backend (D1) all exist as cited and are
  the fuzz activity's inputs.

## Impact

- **New capability spec**: `fuzzing-harness` (ADDED requirements only).
- **Existing specs touched**: none directly; cites `proof-and-sandbox-execution` (sandbox
  execution) and `vuln-class-focus` (class attribution) but adds no deltas to them.
- **Code touched**: a new `fuzz` activity (in `src/quarry_activities/` or the
  `src/quarry_plugins/vuln_classes/` sweep family, ADR-025), a mutation engine module, a
  fuzz-payload → `CandidateFinding` converter in
  `src/quarry_workflows/candidate_sources.py`, a `validate-fuzz-candidate` validator
  activity, and dispatch wiring in the `run_scan.py` HUNT deterministic-sweep block
  (run_scan.py:1755-1792).
- **Deterministic**: same seed + corpus + dictionary + binary → same ordered run sequence.
  No network I/O beyond what the sandbox permits. No model calls.
- **Backward compatible**: no existing activity, schema field, or workflow stage changes.

## Non-goals

- Coverage-guided fuzzing (no coverage feedback loop) — the ticket itself lists this as
  the current gap, and it stays a gap.
- Disassembly, symbolic execution, or concolic exploration.
- A `MEMORY_SAFETY`/`DoS` vulnerability-class enum value (separate change).
- A bundled memory-unsafe crash fixture (separate fixture change).
- Live-network egress during fuzzing (sandbox runs are `--network none` for CLI targets,
  per sandbox.py:319).
- stdin/config_file mutation channels (v1 is args-only; stdin/config_file can be added
  in a follow-on change).
