# 2026-06-02 Dev Log — Command Injection Workflow

## Goal

Add the command-injection vuln class: detect shell sinks, safely prove the
seeded `/debug/ping` injection with an echo marker, and render the proof. Plus
the agreed follow-up: stop `quarry target start` from orphaning its uvicorn child.

## Changed

- `src/quarry_plugins/vuln_classes/command_injection.py` — AST sink scanner
  (`subprocess.*(shell=True)`, `os.system`/`os.popen`) that associates the
  handler request parameter flowing into the sink; emits CRITICAL candidates with
  `{route, param, sink}` metadata. Mirrors `idor.py`.
- `src/quarry_activities/dynamic_validation.py` — `validate_command_injection_candidate`
  safe prover: injects a fixed `127.0.0.1; echo QUARRY_PROOF_<hex>` payload into
  the param, localhost-only via `allowed_hosts`, strict timeout, validated iff the
  marker echoes back; captures HTTP request/response artifacts.
- `src/quarry/schemas.py` — `ValidationResult.safe_payload` (optional) so the
  prover can record the benign payload it used.
- `src/quarry_workflows/run_scan.py` — `CMDI_SCAN` stage mirroring `IDOR_SCAN`,
  building a `FinalFinding` + `ProofArtifact(dynamic_command_injection_echo,
  safe_payload=...)`, threaded through the shared proof plumbing into the report.
  Coverage marks command_injection complete.
- `src/quarry_activities/reporting.py` — proof block now renders `Safe payload`.
- `src/quarry_artifacts/http_utils.py` — artifact keys now include a URL digest so
  multiple requests to the same host (IDOR + command injection) no longer collide
  and overwrite each other's proof artifacts.
- `src/quarry_activities/target.py` + `src/quarry_cli/main.py` — launch the target
  with `start_new_session=True` and add `terminate_local_target`, which kills the
  whole process group (uv run → uvicorn) and closes pipes. `target start` handles
  SIGTERM like Ctrl-C so killing the launcher no longer orphans uvicorn.
- Activities registered in worker, server lifespan, and the test fixture.
- Tests: `test_command_injection_scanner.py`, `test_command_injection_validation.py`,
  golden `test_command_injection_report.py`, fixture
  `expected_command_injection.json`, and `test_command_injection_pipeline` (live
  e2e). Updated `test_idor_pipeline` for the shared multi-class artifact dir and
  bumped the server-lifespan activity count.

## Works

- pyright clean; full suite passes with no warnings.
- Live scan proves the `/debug/ping` injection: the report shows a
  command_injection finding with a `#### Proof: dynamic_command_injection_echo`
  block and the echo-marker safe payload.
- Benchmark: command injection moves from missed → found.
- `quarry target start` no longer leaves an orphaned uvicorn on teardown.

## Commands run

```text
uv run ruff check . && uv run ruff format --check . && uv run pyright
uv run pytest -q -W default
uv run pytest tests/integration/test_e2e_temporal.py -k command_injection -v
```

## Next task

- Week 8: integrations and lifecycle events.

## Open decisions

- The dynamic prover lives in `dynamic_validation.py` next to the IDOR validator
  (the week plan's `proof.py` name was superseded by the established convention).
- Proof payload uses a fixed echo-only template (never arbitrary commands),
  localhost-only, strict timeout — per the prover safety rules.
