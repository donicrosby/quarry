# Tasks: binary-analysis-tools

## 1. Tool module scaffolding
- [ ] Create `src/quarry_tools/binary_analysis.py` with the six tool classes
  (`_FileType`, `_ExtractStrings`, `_Checksec`, `_LinkedLibraries`,
  `_SuidSgidDetect`, `_SymlinkAnalysis`) matching the `ToolSpec` protocol
  (`src/quarry/plugin_types.py:42-52`).
- [ ] Each class SHALL have `name`, `description`, `input_schema`, `roles`,
  and `run(self, inputs, repo_root) -> str`.
- [ ] Roles SHALL include at minimum `recon`, `hunt`, and `prove`.
- [ ] GUARD: `uv run python -c "from quarry_tools.binary_analysis import _FileType;
  print(_FileType().name)"` prints `file_type`.

## 2. Register tools in BUILTIN_REGISTRY
- [ ] Add imports and six entries to `BUILTIN_REGISTRY` in
  `src/quarry_tools/builtins.py`, following the existing pattern at
  lines 198-205.
- [ ] GUARD: `uv run python -c "from quarry_tools.registry import load_registry;
  r = load_registry(); assert 'file_type' in r"` exits 0.

## 3. Implement `_FileType` tool
- [ ] Wrap `file -b <path>` via `subprocess.run` with 10-second timeout,
  confined to `repo_root`.
- [ ] On `FileNotFoundError`, raise `ToolUnavailableError` with message
  naming `file` and an install hint.
- [ ] Unit test: ELF binary returns output containing "ELF"; text file returns
  non-error classification.
- [ ] GUARD: `uv run pytest tests/unit/test_binary_analysis_tools.py -k
  test_file_type -v` — 2+ tests green.

## 4. Implement `_ExtractStrings` tool
- [ ] First attempt: subprocess to system `strings` (binutils) with
  `-n <min_length>` flag.
- [ ] Fallback (when `strings` absent): pure-Python scan for printable
  byte sequences of `min_length` or longer (ASCII printable characters:
  range 0x20-0x7E plus tab 0x09; newline 0x0A terminates the sequence — 
  consistent with GNU `strings` behaviour).
- [ ] `min_length` input key SHALL default to 4.
- [ ] Unit test: synthetic binary with known embedded strings; verify
  extraction with default and custom min_length.
- [ ] GUARD: `uv run pytest tests/unit/test_binary_analysis_tools.py -k
  test_extract_strings -v` — 3+ tests green.

## 5. Implement `_Checksec` tool
- [ ] Wrap `readelf -lW <path>` and `readelf -dW <path>` to inspect
  ELF program headers and dynamic section.
- [ ] Detect: RELRO (GNU_RELRO segment + BIND_NOW → Full, GNU_RELRO only →
  Partial, absent → None), NX (GNU_STACK with execute flag absent →
  Enabled), PIE (ELF type DYN for executable → Enabled), stack canary
  (presence of `__stack_chk_fail` in dynamic symbols → Enabled),
  RPATH/RUNPATH (DT_RPATH/DT_RUNPATH entries).
- [ ] Non-ELF files SHALL return an error message, not a crash.
- [ ] On `FileNotFoundError` for `readelf`, raise `ToolUnavailableError`.
- [ ] Unit test: compile two tiny C binaries — one with
  `-fstack-protector-strong -pie -Wl,-z,relro,-z,now` and one with
  `-z execstack -no-pie -z norelro` — and assert expected flags.
- [ ] GUARD: `uv run pytest tests/unit/test_binary_analysis_tools.py -k
  test_checksec -v` — 3+ tests green.

## 6. Implement `_LinkedLibraries` tool
- [ ] Wrap `readelf -dW <path> | grep NEEDED` to extract sonames.
- [ ] Non-ELF or statically-linked binaries SHALL return a message
  indicating zero dynamic libraries.
- [ ] Unit test: dynamically linked binary lists libc.so.6;
  statically linked binary reports none.
- [ ] GUARD: `uv run pytest tests/unit/test_binary_analysis_tools.py -k
  test_linked_libraries -v` — 2+ tests green.

## 7. Implement `_SuidSgidDetect` tool
- [ ] Walk `repo_root` with `os.walk` (or `pathlib.rglob`), `os.stat` each
  regular file, check `st_mode & (stat.S_ISUID | stat.S_ISGID)`.
- [ ] Each hit SHALL report the repo-relative path and octal mode.
- [ ] Unit test: create a temp file, `chmod u+s`, verify reported;
  `chmod -s`, verify not reported. Also test directory with sgid bit is
  skipped (regular files only).
- [ ] GUARD: `uv run pytest tests/unit/test_binary_analysis_tools.py -k
  test_suid_sgid -v` — 3+ tests green.

## 8. Implement `_SymlinkAnalysis` tool
- [ ] Walk `repo_root`, collect all entries where `path.is_symlink()` is
  true; report link path and resolved target.
- [ ] For hard links: collect `(st_dev, st_ino)` tuples for all regular
  files; report groups where `st_nlink > 1` or where inode appears more
  than once.
- [ ] Unit test: create a symlink and a hard link in a temp dir under
  repo_root; verify both reported.
- [ ] GUARD: `uv run pytest tests/unit/test_binary_analysis_tools.py -k
  test_symlink_analysis -v` — 2+ tests green.

## 9. Implement `binary_analysis` Temporal activity
- [ ] Create `src/quarry_activities/binary_analysis.py` with
  `@activity.defn(name="binary-analysis")` decorator.
- [ ] Activity SHALL: (a) discover ELF binaries under `repo_root` via
  `file_type` on every regular file whose first 4 bytes match ELF magic
  (`\x7fELF`), (b) run `checksec`, `linked_libraries`, `extract_strings` on
  each discovered binary, (c) run `suid_sgid_detect` and `symlink_analysis`
  once over the whole tree, (d) assemble a structured report dict with key
  `binaries` (list of per-binary reports) plus `suid_sgid` and `symlinks`
  sections, (e) persist the report as a scan artifact under the key
  `"binary_analysis"` using `LocalArtifactStore` at the artifact_root path
  (activities receive artifact_root as an explicit arg — pattern at 
  run_scan.py:612/694/764), and (f) record the artifact key on the scan 
  metadata for downstream reference at consumption time.
- [ ] Activity SHALL be deterministic: same repo state → same report.
- [ ] Activity SHALL NOT crash on missing tool binaries; absent tools
  produce a `tool_unavailable` field in the report for that check.
- [ ] Unit test: repo with zero binaries yields empty report (no crash,
  `binaries` list empty, `suid_sgid` and `symlinks` sections empty).
- [ ] GUARD: run against `examples/vulnerable-cli` after `cargo build
  --release` in the workspace; verify report structure has `binaries[...]`
  with `file_type`, `checksec`, `linked_libraries` fields.

## 10. Create `BinaryAnalysisContextInjector` plugin
- [ ] Create `src/quarry_plugins/context/binary_analysis_context.py`
  implementing the `ContextInjectorPlugin` protocol
  (`src/quarry_plugins/base.py:104-119`), following the `kb_context.py`
  pattern.
- [ ] `attack_classes` SHALL be `frozenset({VulnerabilityClass.SECURITY_MISCONFIGURATION})`.
- [ ] `priority` SHALL be 40 (below `kb_context` at 50 — ascending sort at
  budget.py:60 puts lower-priority plugins first; binary analysis report is
  more specific than KB context and should lead).
- [ ] `__init__` SHALL accept `artifact_root: str | None` (mirroring
  KbContextInjectorPlugin at kb_context.py:34), so the plugin is
  instantiated with the per-scan artifact root at consumption sites
  (hunt.py:206, gapfill.py:339) rather than resolved from a process-global
  singleton at emit time.
- [ ] `inject_context()` SHALL read the persisted `"binary_analysis"` report
  artifact from the artifact store and return the report text, or `None`
  when the artifact is absent or the task's `vuln_class` is not
  `SECURITY_MISCONFIGURATION`. The assembler (budget.py:61) adds the
  `## Domain context: {name}` header from `plugin.name`; the plugin SHALL
  return the body text only.
- [ ] Unit test: injector returns `None` when no binary report artifact
  exists; returns report block when artifact is present.

## 11. Wire `binary_analysis` activity and context injector into scan workflow
- [ ] Add a `binary_analysis` activity invocation inside the RECON stage of
  `RunScanWorkflow` in `src/quarry_workflows/run_scan.py`, positioned
  after `kb-recon` and before `emit-agent-tasks` (lines 796-797).
- [ ] The workflow SHALL invoke `binary-analysis` activity and pass the
  artifact root so the report is persisted.
- [ ] Register `BinaryAnalysisContextInjector` as an entry-point singleton
  under the `quarry.plugins` group (pyproject.toml, mirroring kb_context at
  line 63) — the singleton has artifact_root=None and returns None at emit
  time (portability invariant); real resolution happens at consumption.
- [ ] Wire injection at hunt consumption: in
  `src/quarry_activities/hunt.py`, construct
  `BinaryAnalysisContextInjector(artifact_root=artifact_root)` alongside the
  existing `KbContextInjectorPlugin` construction (line 206), and merge
  the returned text into the task's domain_context before rendering.
- [ ] Wire injection at gapfill consumption: in
  `src/quarry_activities/gapfill.py`, construct
  `BinaryAnalysisContextInjector(artifact_root=artifact_root)` alongside the
  existing `KbContextInjectorPlugin` construction (line 339), and merge
  the returned text into the task's domain_context for re-hunt tasks.
- [ ] Integration test assertions: (a) a `security_misconfiguration` hunt
  task's effective `domain_context` contains the binary report and
  `domain_context_sources` includes `binary_analysis`; (b) a `command_injection`
  task has NO binary analysis content in its `domain_context`; (c) the
  workflow does not crash when the binary report artifact is absent
  (injector returns `None`).
- [ ] Integration test assertion: gapfill-emitted `security_misconfiguration`
  task (gapfill-coverage return) receives binary analysis context in the
  same way as initial-emission tasks.
- [ ] GUARD: `uv run pytest tests/integration/ -k
  test_binary_analysis_in_scan -v` exits 0.

## 12. Security confinement tasks (requirement 9)
- [ ] Unit test: path-escape-is-refused-by-runner — construct a binary
  analysis tool input with a path outside repo_root; assert
  `ToolRunner` raises `ToolSecurityError` before the tool executes.
- [ ] Unit test: tool-never-writes-files — invoke every binary analysis
  tool against a repo with known file count; assert no new files are
  created and no existing files are modified (compare `os.stat` before/after
  or check file count).
- [ ] GUARD: `uv run pytest tests/unit/test_binary_analysis_tools.py -k
  test_security -v` — 2+ tests green.

## 13. Golden smoke test against vulnerable-cli
- [ ] Ensure `examples/vulnerable-cli` builds cleanly: `cd
  examples/vulnerable-cli && cargo build --release`.
- [ ] Run the `binary_analysis` activity against `examples/vulnerable-cli`
  repo root.
- [ ] Assertions: (a) the report contains the compiled binary —
  `target/release/vulnerable-cli` is present; cargo may produce a hardlink
  pair (`target/release/vulnerable-cli` and a deps artifact sharing the same
  inode, `st_nlink >= 2`); the report SHALL list both paths when they exist
  (see requirement 7), (b) `checksec` fields are present, (c)
  `linked_libraries` lists at minimum libc and libgcc_s, (d)
  `suid_sgid_detect` reports zero findings, (e) `symlink_analysis` reports
  any hardlink pairs discovered (may be non-empty due to cargo's release
  build hardlink; zero findings is also acceptable when no hardlinks were
  produced).
- [ ] GUARD: `uv run pytest tests/golden/test_binary_analysis_golden.py -v`
  — 5 assertions green.

## 14. Validate, commit, and push
- [ ] `npx openspec validate binary-analysis-tools --strict` exits 0.
- [ ] `git add openspec/changes/binary-analysis-tools/ && git commit -m
  "spec: add binary-analysis-tools change"`.
- [ ] Push branch `spec/binary-analysis-tools` to origin (try `gh auth
  setup-git && git push -u origin spec/binary-analysis-tools`; park
  locally on credential failure).
- [ ] Report commit SHA in run metadata.