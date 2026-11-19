# Change: tempfile-race-terminal-escape

## Why

Quarry's `VulnerabilityClass` enum (18 members at b284af7) omits two important
CLI-side vulnerability patterns: tempfile races (predictable names in shared
directories, mktemp misuse, TOCTOU windows) and terminal escape injection
(attacker-controlled input echoed to a terminal without ANSI sanitization).
Both are common in CLI tools and shell scripts — the same surface where Quarry
already detects command injection and path traversal — yet no hunter or
deterministic scanner exists for either class.

## What Changes

- **Two new `VulnerabilityClass` members**: `tempfile_race` and
  `terminal_escape`, each with a scoped definition so focus resolution and the
  class-coverage floor apply.
- **Deterministic scanner plugins**: per-class scanner activities (analogous to
  the existing `secrets.py` and `ssrf.py` plugins) that regex-scan source files
  for unsafe tempfile patterns and unsanitized terminal-output patterns. The
  scanners produce `CandidateFinding` objects — exactly like the SSRF sink
  scanner — so candidates flow through the normal validate/dedup/promotion
  pipeline.
- **Hunt templates**: per-class prompt templates under `prompts/hunt/` so the
  agentic hunter can reason about tempfile-race source→sink traces and
  terminal-escape injection paths. The existing hunt-stage requirement ("Every
  vulnerability class is huntable") automatically mandates these when new enum
  members are added.
- **Proof patterns** use the existing sandbox infrastructure (`input_files`
  staging in `sandbox_tool.py:66-69`; stdout capture in `sandbox_exec.py:207`)
  — no new sandbox capability is needed.

## Impact

- **Specs**: `vuln-class-focus` (2 ADDED requirements — class definitions),
  `plugin-framework` (2 ADDED requirements — deterministic scanner activities).
- **Code**: `quarry/schemas.py` (2 enum members), `quarry_plugins/vuln_classes/`
  (2 new scanner modules: `tempfile_race.py`, `terminal_escape.py`),
  `prompts/hunt/` (2 new Jinja2 templates).
- **Fixtures**: `vulnerable-cli` must gain tempfile-race and terminal-echo
  subcommands for acceptance testing; this is an implementation task, not a
  spec requirement. The existing CI test `test_vulnerable_cli.py` follows the
  same pattern for command_injection.
- **Cost**: negligible — the deterministic scanners add ~200 lines each
  (same complexity tier as `ssrf.py`), and hunt templates add one model round
  per (class, scope) when these classes are in focus.
- **Non-goals**: A general runtime TOCTOU race detector (requires OS-level
  interception, not static analysis); terminal escape detection in web/HTTP
  responses (CLI scope only); exhaustive ANSI escape catalogues (detect
  the pattern, leave exploitability adjudication to the agentic ensemble).

## Reconciliation against main @ b284af7

The original ticket (t_6428a1ed, 2026-09-10, ~45 merges ago) reconciled:

- `input_files` staging for pre-planted files: **VERIFIED** present
  (`src/quarry_tools/sandbox_tool.py:66-69`).
- Stdout capture in sandbox: **VERIFIED** present
  (`src/quarry_activities/sandbox_exec.py:207`).
- Per-class hunt template loading: **VERIFIED** present
  (`src/quarry_activities/hunt.py:229-230`).
- `tempfile_race` / `terminal_escape` in VulnerabilityClass: **VERIFIED absent**
  (`src/quarry/schemas.py:92-111` — 18 classes, neither present).
- Deterministic scanners for these classes: **VERIFIED absent**
  (`src/quarry_plugins/vuln_classes/` — only `secrets.py` and `ssrf.py`).

**Dropped**: "Proven on vulnerable-cli" as an immediate spec requirement —
extending vulnerable-cli with tempfile-race and terminal-echo subcommands is an
implementation task following the same pattern as the existing
command_injection subcommand; the spec defines the requirements, and acceptance
is tested during implementation. "Verdict helper" as a separate concept is
subsumed by the existing deterministic-scanner-plugin pattern (cf. `ssrf.py`).