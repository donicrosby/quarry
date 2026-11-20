## ADDED Requirements

### Requirement: Deterministic non-agentic fuzz activity

A new `fuzz` activity SHALL run a built target repeatedly in the sandbox and SHALL make
no model call. Given the same seed, corpus, dictionary, and target binary, it SHALL
produce the same ordered run sequence, so a fuzz pass is reproducible.

#### Scenario: reproducible-run-sequence

- **WHEN** two fuzz passes run with the same seed, corpus, dictionary, and binary
- **THEN** both passes emit the same ordered sequence of mutated inputs

#### Scenario: no-model-call-in-fuzz-loop

- **WHEN** the fuzz activity runs to completion
- **THEN** it performs zero `ModelClient` calls (no `complete_structured`, no `run_agent_loop`)

### Requirement: Target build and invocation are sourced from recon

The `fuzz` activity SHALL obtain the target's build recipe from `BuildCommand`
(schemas.py:1176) and its invocation from `EntryPoint.invocation` plus
`attacker_controlled_input` (schemas.py:1104-1105); it SHALL NOT guess how to build or
invoke the target.

#### Scenario: missing-invocation-is-refused

- **WHEN** an entry point has an empty `invocation` or `attacker_controlled_input` is `"none"`
- **THEN** the fuzz activity refuses to run that entry point and records the refusal

#### Scenario: build-command-is-honored

- **WHEN** a `BuildCommand` with `purpose` `build` or `fuzz` is present
- **THEN** the fuzz activity runs that command to produce the binary before fuzzing

### Requirement: Mutation strategies cover bit, byte, and dictionary edits

The mutation engine SHALL implement bit flip, byte insert, byte delete, and dictionary
substitution/insertion. Mutations SHALL apply to the entry point's
`attacker_controlled_input` channel. In v1 the only supported channel is `args`; stdin
and config_file channels are out of scope. Dictionary tokens SHALL be configurable and
default to format-string, path-traversal, and shell-metacharacter payloads.

#### Scenario: each-strategy-is-applied

- **WHEN** a fuzz pass runs enough iterations
- **THEN** bit flip, byte insert, byte delete, and dictionary mutations each appear at least once

#### Scenario: dictionary-payloads-reach-the-input

- **WHEN** the default dictionary is in effect
- **THEN** generated inputs include format-string and path-traversal payloads from the dictionary

#### Scenario: non-args-channel-is-skipped-in-v1

- **WHEN** an entry point's `attacker_controlled_input` is `stdin`, `config_file`, `env`, or `none`
- **THEN** the fuzz activity skips that entry point and records the skip reason

### Requirement: Crash classification distinguishes signals, sanitizer output, and boundary outcomes

The crash classifier SHALL decode negative and >=128 exit codes as signal deaths across
both backends (sandbox.py:256, sandbox.py:376). Deaths from sandbox rlimits SHALL be
boundary, not crash: SIGKILL (−9)/SIGXCPU (−24) from RLIMIT_CPU, SIGABRT (−6) from
RLIMIT_AS without sanitizer output (sandbox.py:136-139), and wall-clock timeouts
(exit_code 124, timed_out=True). ASan/UBSan stderr SHALL classify as a crash regardless
of exit code; MSan/TSan are not addressed in v1.

#### Scenario: negative-exit-code-is-a-crash

- **WHEN** a run returns `exit_code: -11` and `timed_out` is false
- **THEN** the run is classified as a crash with signal SIGSEGV

#### Scenario: exit-128-plus-n-is-a-crash

- **WHEN** a run returns `exit_code: 139` (128+11) and `timed_out` is false
- **THEN** the run is classified as a crash with signal SIGSEGV

#### Scenario: rlimit-signal-is-boundary-not-crash

- **WHEN** a run returns `exit_code: -9` (SIGKILL from RLIMIT_CPU soft==hard, sandbox.py:136-137)
  or `exit_code: -24` (SIGXCPU from RLIMIT_CPU soft<hard) with `timed_out` false
- **THEN** the run is NOT classified as a crash and is recorded as a boundary outcome

#### Scenario: wall-clock-timeout-is-boundary

- **WHEN** a run returns `exit_code: 124` and `timed_out` is true (wall-clock timeout,
  sandbox.py:262-265)
- **THEN** the run is NOT classified as a crash and is recorded as a boundary outcome

#### Scenario: sanitizer-output-is-a-crash

- **WHEN** a run's stderr matches an ASan/UBSan error signature
- **THEN** the run is classified as a crash with the sanitizer kind recorded

#### Scenario: positive-nonzero-exit-is-not-a-crash

- **WHEN** a run returns `exit_code: 1` with no sanitizer output
- **THEN** the run is not classified as a crash and no candidate is emitted for it

### Requirement: Crash dedup by output hash

Unique crashes SHALL be deduplicated by a deterministic crash hash computed from
normalized stderr, exit code, and signal, so repeated runs hitting one crash emit one
candidate. Backtrace-based dedup SHALL NOT be required (the sandbox captures no
backtrace).

#### Scenario: same-crash-emits-one-candidate

- **WHEN** multiple runs produce the same crash signature (same signal and normalized stderr)
- **THEN** exactly one candidate is emitted for that crash

#### Scenario: distinct-crashes-stay-distinct

- **WHEN** two crashes differ in signal or normalized stderr signature
- **THEN** they produce distinct crash hashes and distinct candidates

### Requirement: Fuzz dispatch gates on single-class focus

The fuzz activity SHALL only dispatch when the scan's resolved focus contains exactly one
`VulnerabilityClass`. When focus is multi-class or defaults to all classes, the activity
SHALL skip the entry point and record the skip reason. This ensures `vuln_class`
attribution is deterministic without requiring a `MEMORY_SAFETY` enum addition (which is a
separate change).

#### Scenario: single-class-focus-dispatches

- **WHEN** the scan's resolved focus contains exactly one class (e.g. `[COMMAND_INJECTION]`)
- **THEN** fuzz dispatches and attributes all crashes to that class

#### Scenario: multi-class-focus-skips

- **WHEN** the scan's resolved focus contains multiple classes or the default ALL set
- **THEN** fuzz skips the entry point and records the skip reason in the scan events

### Requirement: One CandidateFinding per unique crash

Each unique crash SHALL produce one `CandidateFinding` (schemas.py:641) with
`trigger_input` set to the crashing input, `metadata.source` set to `"fuzz"`, and the
crash hash, signal (or sanitizer kind), and seed in `metadata`. `vuln_class` SHALL be the
scan's single focused class (per the single-class-focus dispatch gate).

#### Scenario: candidate-emitted-per-unique-crash

- **WHEN** a unique crash is identified
- **THEN** one `CandidateFinding` is created with `trigger_input` set to the crashing input

#### Scenario: crash-metadata-carries-hash-and-kind

- **WHEN** a crash candidate is created
- **THEN** `metadata` carries `source`, the crash hash, the signal (or sanitizer kind), and the seed

### Requirement: Bounded fuzz budget and sandbox containment

The `fuzz` activity SHALL cap total runs and per-run timeout and SHALL stop, not run
unbounded, when the budget is exhausted. Every run SHALL execute through a
`SandboxBackend` so rlimits and allowlist apply; scrub is the activity layer's
responsibility (see Crash output is scrubbed and stored as artifacts — the backend returns pre-scrub results, sandbox.py:51-54).

#### Scenario: run-budget-caps-total-runs

- **WHEN** the configured run budget is reached
- **THEN** the fuzz activity stops issuing runs and reports the number of runs completed

#### Scenario: every-run-goes-through-sandbox-backend

- **WHEN** the sandbox backend refuses a command (not on the allowlist)
- **THEN** the fuzz activity fails closed and does not bypass the backend

### Requirement: Crash output is scrubbed and stored as artifacts

Crash output (stderr, sanitizer reports) SHALL pass through `Scrubber.scrub()` and
`<target_content>` wrap and be stored as artifacts (TOOL_STDERR), never inline, mirroring
`sandbox_exec_activity`.

#### Scenario: crash-output-is-scrubbed

- **WHEN** a crash run's stderr contains credential-shaped text
- **THEN** the stored artifact is scrubbed and wrapped in `<target_content>`

#### Scenario: crash-output-stored-not-inline

- **WHEN** a crash run completes
- **THEN** stderr is stored as an artifact ref, not embedded in the candidate's text fields

### Requirement: Fuzz-candidate validation mirrors secrets precedent

Fuzz candidates SHALL pass through a dedicated inline validator
(`validate-fuzz-candidate` activity) mirroring the secrets validation pattern
(run_scan.py:1755-1792). The validator SHALL promote candidates with valid crash
signatures to `FinalFinding` and SHALL reject candidates whose crash metadata is
inconsistent (e.g. missing hash, zero-length stderr without a sanitizer match).

#### Scenario: valid-crash-candidate-is-promoted

- **WHEN** a fuzz candidate carries a valid crash hash, signal or sanitizer kind, and non-empty trigger_input
- **THEN** the validator promotes it to a `FinalFinding`

#### Scenario: inconsistent-crash-candidate-is-rejected

- **WHEN** a fuzz candidate has a crash hash but no signal and no sanitizer kind
- **THEN** the validator rejects it and records the rejection reason
