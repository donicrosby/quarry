# Tasks

## 1. Schema: enum members

- [ ] 1.1 Add `tempfile_race` and `terminal_escape` to `VulnerabilityClass` enum in `src/quarry/schemas.py`
- [ ] 1.2 Verify focus machinery picks up both classes with no list edits: `resolve_focus()` defaults to `list(VulnerabilityClass)` (`src/quarry/panel_config.py:425`), so new enum members are automatically valid focus values, included in the default class set, and listed in the invalid-focus error (covered by `tests/unit/test_panel_config.py`)
- [ ] 1.3 Verify that `VulnerabilityClass` string values match hunt template filenames (`tempfile_race` → `prompts/hunt/tempfile_race.1.0.0.j2`)

## 2. Deterministic scanner: tempfile_race

- [ ] 2.1 Create `src/quarry_plugins/vuln_classes/tempfile_race.py`
- [ ] 2.2 Implement regex patterns: predictable `/tmp/*` paths, `tempfile.mktemp()`, `os.tmpnam()`, `tmpnam()`, `mktemp` without `--tmpdir`
- [ ] 2.3 Implement `scan_file_for_tempfile_races()` and `scan_repo_for_tempfile_races()` activity
- [ ] 2.4 Implement `tempfile_match_to_candidate_finding()` converter (fingerprint, root cause key, evidence path)
- [ ] 2.5 Register the activity via `@activity.defn` decorator
- [ ] 2.6 Unit tests: predictable path detected, deprecated API detected, safe patterns not flagged, binary files skipped

## 3. Deterministic scanner: terminal_escape

- [ ] 3.1 Create `src/quarry_plugins/vuln_classes/terminal_escape.py`
- [ ] 3.2 Implement regex patterns: user input echoed via `print()`/`echo`/`printf`/`write()` to stdout/stderr without ANSI stripping
- [ ] 3.3 Implement `scan_file_for_terminal_escapes()` and `scan_repo_for_terminal_escapes()` activity
- [ ] 3.4 Implement `terminal_match_to_candidate_finding()` converter
- [ ] 3.5 Register the activity via `@activity.defn` decorator
- [ ] 3.6 Unit tests: unsanitized print detected, sanitized output not flagged, binary files skipped

## 4. Hunt templates

- [ ] 4.1 Create `prompts/hunt/tempfile_race.1.0.0.j2` — model prompt for tempfile-race source→sink tracing
- [ ] 4.2 Create `prompts/hunt/terminal_escape.1.0.0.j2` — model prompt for terminal-escape injection tracing
- [ ] 4.3 Verify both templates render with the standard hunt context (via `build_prompt` unit test or manual render check)

## 5. Integration: workflow wiring

- [ ] 5.1 Wire tempfile_race scanner into the scan workflow pre-hunt sweep (same pattern as SSRF scanner)
- [ ] 5.2 Wire terminal_escape scanner into the scan workflow pre-hunt sweep
- [ ] 5.3 Verify scanner candidates flow through validate/dedup/promotion pipeline end to end

## 6. vulnerable-cli fixture extension

- [ ] 6.1 Add `--write-temp` subcommand to `vulnerable-cli` that writes to a predictable `/tmp` path
- [ ] 6.2 Add `--echo-input` subcommand that echoes user input to stdout without ANSI sanitization
- [ ] 6.3 Add ground-truth entries to `tests/golden/ground_truth/vulnerable-cli.json` for both new vulns
- [ ] 6.4 Integration tests: tempfile race proof via `input_files` pre-plant; terminal escape proof via injected ANSI verified in stdout
- [ ] 6.5 Rebuild vulnerable-cli binary and verify existing tests still pass

## 7. Validation and gates

- [ ] 7.1 Run `uv run ruff check .` and `uv run ruff format --check .` (repo-wide, matching the CI gate)
- [ ] 7.2 Run `uv run pyright` (strict, repo-wide) and `uvx --from 'vulture==2.16' vulture src ci/vulture_allowlist.py --min-confidence 60`
- [ ] 7.3 Run full unit test suite: `uv run pytest tests/unit -q`
- [ ] 7.4 Run integration tests: `uv run pytest tests/integration/test_vulnerable_cli.py -q`
- [ ] 7.5 Run golden tests: `uv run pytest tests/golden -q` (verify new ground-truth entries)
- [ ] 7.6 Verify `npx --yes @fission-ai/openspec validate tempfile-race-terminal-escape --strict` exits 0, warning-free (config.yaml rules scalars are quoted)

## 8. Landing

- [ ] 8.1 Conventional commit, push, CI green
- [ ] 8.2 `npx --yes @fission-ai/openspec archive tempfile-race-terminal-escape --yes`
