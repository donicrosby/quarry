# Proposal: binary-analysis-tools

## Why

Quarry currently has no tools for static binary inspection. A CLI binary or
compiled artifact sitting in a target repo is invisible to the hunter:
it cannot see the file type, cannot extract embedded strings, cannot audit
the hardening profile (RELRO / NX / PIE / canary), cannot inventory the linked
libraries, and cannot detect dangerous SUID/sgid bits or symlinks. This is a
blind spot for the `security_misconfiguration` vulnerability class, which the
domain model already carries (`src/quarry/schemas.py:109`) but for which no
dedicated tooling exists.

The existing tool infrastructure — `ToolSpec` protocol
(`src/quarry/plugin_types.py:42-52`), `ToolRunner` repo-root confinement
(`src/quarry_tools/runner.py:41-50`), `ToolUnavailableError`
(`src/quarry_tools/errors.py:14-15`), and the `BUILTIN_REGISTRY` pattern
(`src/quarry_tools/builtins.py:198-205`) — provides a well-defined surface for
adding read-only, confined binary analysis tools that agents can call during
the hunt loop.

## What Changes

1. **Six new binary analysis tools** registered in the tool registry:
   `file_type`, `extract_strings`, `checksec`, `linked_libraries`,
   `suid_sgid_detect`, `symlink_analysis`. Each wraps an external system
   binary (`file`, `strings`, `readelf`) or reads OS filesystem
   metadata directly.

2. **A `binary_analysis` Temporal activity** that runs a deterministic pass
   over the repo root, invokes the tools for every discovered binary, and
   produces a structured binary hardening report.

3. **The report feeds the hunt stage** as domain context on `AgentTask`,
   so hunters inspecting a `security_misconfiguration` task see the hardening
   profile without needing to call each tool individually during the loop.

4. **Golden smoke test**: binary analysis on `examples/vulnerable-cli` after
   `cargo build --release` produces a hardening report identifying at minimum
   the file type, linked libraries, and absence of SUID/sgid bits.

## Impact

- **New capability spec**: `binary-analysis` (ADDED requirements only).
- **Existing specs touched**: none (this is a greenfield capability).
- **Code touched**: new files in `src/quarry_tools/` (tools),
  `src/quarry_activities/` (activity), plus wiring into the `BUILTIN_REGISTRY`
  and `RunScanWorkflow`.
- **External dependencies**: `file`, `strings`, `readelf` (`strings` and
  `readelf` from binutils; `file` from the file/libmagic package;
  `ToolUnavailableError` when absent, consistent with existing opengrep/SCIP
  pattern).
- **Deterministic**: same binary → same report. No network I/O. Read-only.
- **Backward compatible**: no existing tool or activity changes.

## Non-goals

- Disassembly or decompilation (binaryninja/ghidra class — out of scope).
- Dynamic analysis (sandbox execution of the binary — covered by
  `proof-and-sandbox-execution`).
- Windows PE or macOS Mach-O support in the initial slice (ELF-only for
  checksec and linked_libraries; file_type and strings work across formats).
- Runtime hardening detection (e.g. `checksec --kernel`) — static only.