# Change: prompt-replay-harness

## Why

Iterating on a prompt template or the reasoning/parsing logic around it
currently requires a **full scan** — ~$0.40 and ~2h wall-clock — just to see how
one role behaves against real input. That feedback loop is too slow for prompt
engineering, which needs many cheap iterations against *realistic* state.

The repo already proves the value of the alternative: `scripts/replay_validate.py`
replays the validate ensemble (reasoner + debater) against a single candidate
pulled from a prior scan's DB, using the current code + prompt templates, for
cents in seconds. But it covers **only the validate stage**. Hunt, gapfill,
prove, trace, and recon have no equivalent — a hunt-prompt change can't be
evaluated against the real repo + KB state a scan would have seen without
re-running the whole pipeline.

The durable fix is a **generalized direct-activity replay harness**: given a
prior scan's persisted state (candidates, agent tasks, KB artifacts, panel
config), invoke any single agentic activity directly — bypassing the Temporal
workflow — with either real models (through the LiteLLM proxy, like
`replay_validate.py`) or mock models (structural smoke, zero cost).

This is NOT the sync `run_scan()` scaffold (which produces no findings and
can't isolate a stage), and not `scan rerun --mode replay` (which re-renders
the *report* from stored findings with no model calls). Neither lets you test a
prompt mid-pipeline.

## What Changes

- **`quarry replay` CLI command group** (new): one subcommand per agentic
  stage — `replay hunt|gapfill|validate|prove|trace|recon`. Each resolves its
  inputs from a prior scan's DB + artifact store, invokes the activity function
  directly, and prints the structured result. `replay validate` supersedes
  `scripts/replay_validate.py` (which is kept as a thin shim or retired).
- **Input resolvers** (new, `src/quarry_replay/`): per-stage functions that
  reconstruct an activity's call arguments from persisted scan state —
  candidate findings, agent tasks, KB artifacts, target repo path, panel JSON,
  budget caps. Fail loudly when the scan predates a required input rather than
  fabricating one.
- **Model routing parity**: replay uses the SAME `load_quarry_config` +
  `resolve_panel` path as a real scan, so it hits the LiteLLM proxy and the
  configured model tier (never direct to a provider, never the all-mock
  `DEFAULT_PANEL` silently). A `--mock` flag explicitly selects the mock panel
  for zero-cost structural checks, and this choice is printed in the output
  header so a mock result is never mistaken for a real one.
- **Provenance tagging**: replay invocations are recorded with a marker
  distinguishing them from scan invocations (so replay spend/telemetry doesn't
  pollute scan provenance) — replay runs still cost real money against the
  proxy and must be attributable.
- **Golden-fixture replay tests**: each stage gets a mock-panel test asserting
  the harness drives the activity end-to-end (input resolves, activity runs,
  result is structurally valid) with no network and no Temporal server.

## Impact

- **Specs**: new capability `prompt-replay-harness` (this change's spec delta).
  Does not modify existing spec requirements; it is additive tooling.
- **Code**: new `src/quarry_replay/` package; `quarry replay` CLI in
  `src/quarry_cli/`; input resolvers reading `quarry_persistence` and the
  artifact store; `scripts/replay_validate.py` retired or shimmed. No changes
  to the scan workflow, activities' internals, or prompt templates.
- **Behavior contract**: replay NEVER mutates scan state — it is read-only
  against the DB and artifact store, and its model invocations are tagged as
  replay, not scan. A replay must be safely runnable against a production DB
  without touching the recorded scan.
- **Non-goals**: changing any prompt template, changing activity logic,
  running stages concurrently, re-running a whole pipeline. This is a
  single-stage, single-invocation iteration tool.
- **Risk**: low — additive CLI + resolver package. The main correctness risk
  is an input resolver reconstructing the WRONG arguments (stale schema,
  fabricated fallback) and producing a misleading replay; mitigated by
  fail-loud resolvers + mock-panel golden tests that pin the reconstructed
  input shape.
