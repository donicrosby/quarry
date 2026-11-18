# Quarry

Quarry is a local-first, Temporal-orchestrated agentic vulnerability research harness. A
recon agent maps the architecture of any repository (languages, subsystems, entry points,
trust boundaries), then hunter agents investigate across 18 vulnerability classes, an
adversarial validation stage (negative-constraint checklist refuter + optional tiered
debater ensemble) tries to refute each candidate from the code, validated findings get a
severity calibration pass and — for findings that warrant it — a safe local proof
(exploit chain) and a reachability trace, and the scan closes with a production-file
coverage ledger (covered / intentionally-excluded / gap), exploratory gapfill injection,
and a Markdown report with full provenance.

## Quickstart

### Option A — everything in Docker

Brings up Temporal, the API server (port 8000), and the worker in one command:

```bash
docker compose up --build -d        # or: task compose-up
curl localhost:8000/healthz         # {"status":"ok"}
```

The server runs with `--no-worker`; the dedicated `worker` container owns the
Temporal task queue. Model/git secrets are passed through from your shell or a
`.env` file — see `.env.example`. Stop with `docker compose down`.

### Option B — local dev (uv)

Start the supporting services in separate terminals:

```bash
# 1. Temporal server (the server + worker services are also defined here)
docker compose up -d temporal

# 2. Vulnerable-FastAPI target (port 9000)
task target
# or the Node/Express target (port 3000):
# cd examples/vulnerable-express && npm install && node app.js

# 3. Quarry server + worker (port 8000)
uv run quarry server
```

### Run the demo

```bash
uv sync --extra dev
task demo
```

`task demo` checks that the server and target are reachable before running. If any
prerequisite is down it prints the exact commands to start it.

### What you get

After a successful scan:

- **Architecture doc** — `ArchitectureDoc` with detected languages, subsystems, entry
  points, trust boundaries, and build commands, produced by the recon agent, plus a
  rendered attack-surface summary (`reports/<scan_id>-architecture.md`).
- **Findings** — candidates across 18 vulnerability classes (secrets, IDOR,
  command-injection, SSRF, SQLi, XSS, path traversal, SSTI, insecure deserialization,
  auth, security misconfiguration, and more), each validated by an adversarial
  checklist-refuter pass, severity-calibrated, and carrying a fingerprint and — where
  warranted — a safe local proof artifact and reachability trace.
- **Knowledge base** — a per-scan KB root index (`kb-recon`) whose referenced records
  inject as context into hunt/gapfill/validate prompts.
- **Coverage ledger** — which production files were covered, intentionally excluded
  (tests / vendored / generated / out-of-scope, each with a recorded reason), or left as
  honest gaps, plus exploratory gapfill injection against uncovered areas.
- **Markdown report** — `.quarry/reports/<scan_id>.md` with findings, provenance, and
  coverage summary.
- **Dry-run integrations** — Jira and Slack delivery payloads written to
  `.quarry/artifacts/` (no external calls).

View scan status while it runs:

```bash
uv run quarry tui --db .quarry/quarry.db
```

Limit the scan to specific vulnerability classes:

```bash
uv run quarry scan run --repo . --focus ssrf,xss
```

Invalid class names fail fast with the list of valid choices:

```bash
uv run quarry scan run --repo . --focus bogus   # exits with error + valid list
```

List scans and open the report:

```bash
uv run quarry scan list
cat .quarry/reports/<scan_id>.md
```

### Configuration (optional)

Copy `quarry.toml.example` to `quarry.toml` in your project root to configure model
panels and scan defaults without environment variables:

```bash
cp quarry.toml.example quarry.toml
```

A role can be a single model or a tiered ensemble (a SOTA `reasoner` plus an
independent, cheaper `debater` that argues to refute each candidate from the code).
Cross-model disagreement becomes an ordinal credibility signal on the finding
(refuted / contested / unrefuted) rather than a discarded boolean — see
`quarry.toml.example` for the tiered-panel, `vendor_allowlist`, per-role `rpm` rate
limiting, and multi-vendor (Anthropic / Bedrock) options.

Never store API keys in `quarry.toml` — Quarry rejects the file at startup if it
finds credential-like keys.

For the full map of every knob — prompt template versions, panel resolution,
`scan_defaults` fields, budget enforcement — see
[`docs/config-inventory.md`](docs/config-inventory.md).

#### Tuning scan concurrency

Stage-level fan-out within a scan is bounded by `scan_defaults` knobs in
`quarry.toml`:

| Knob | Stage | Default |
|---|---|---|
| `hunt_max_concurrent` | Per-class hunt tasks | 8 |
| `validate_max_concurrent` | Candidate validations | 8 |
| `trace_max_concurrent` | Per-finding reachability traces | 4 |
| `calibrate_max_concurrent` | Per-finding severity calibrations | 4 |
| `prove_max_concurrent` | Per-finding PROVE attempt loops | 4 |
| `dynamic_validate_max_concurrent` | Pre-hunt per-class dynamic-validation sweep | 8 |

Each bound is enforced by a semaphore in the workflow; a higher value increases
parallelism but not total model invocations. Per-role `rpm` token buckets
(see `quarry.toml.example`) remain the global rate guard on top of these bounds.

### Re-render a report (replay)

Re-render a report from stored state without re-running the scan or making model calls:

```bash
uv run quarry scan rerun <scan_id>
```

## CI/CD integrations

The SARIF sink is a built-in finding sink: every scan writes a SARIF 2.1.0 log to
`sarif/<scan_id>.sarif.json` under the scan's artifact root (default
`.quarry/artifacts/`). The log maps each finding's severity to a SARIF
`result.level`, its fingerprint to `partialFingerprints.quarryFingerprint`, and its
primary source location to `locations[0].physicalLocation`. The original, unmapped
severity is carried in `properties.quarry.severity` because the level mapping
collapses `low` and `info` onto `note`, and `properties.quarry.severity_rationale_state`
(`model` / `legacy` / `model_omitted`) reports how the finding's severity rationale
was produced. Gating always uses the severity enum — never the model-authored
rationale prose, which is not exported. Source paths are URI-escaped in
`artifactLocation.uri`, and location resolution mirrors the report's evidence links
(`evidence_path` first, then `source_refs`).

### GitHub Action

`.github/workflows/quarry-scan.yml` is a reusable workflow (`workflow_call`). It
checks out the calling repository, installs Quarry, runs a scan, filters the SARIF
log to `severity_threshold`, uploads it to GitHub code scanning (category
`quarry`), and fails the check when findings at or above the threshold remain.

| Input | Required | Default | Meaning |
|---|---|---|---|
| `quarry_config` | yes | — | Path to the Quarry config file (`quarry.toml`) |
| `target_repo` | no | `${{ github.workspace }}` | Repository path to scan |
| `severity_threshold` | no | `low` | Minimum severity that fails the check |
| `quarry_version` | no | `latest` | Quarry git ref to check out and install |

Example caller:

```yaml
jobs:
  quarry:
    uses: donicrosby/quarry/.github/workflows/quarry-scan.yml@main
    with:
      quarry_config: quarry.toml
      severity_threshold: high
    secrets:
      quarry_model_api_key: ${{ secrets.CHUTES_API_KEY }}
```

### GitLab CI/CD component

`templates/quarry-sast.yml` is a GitLab CI/CD component. It scans
`$CI_PROJECT_DIR`, filters the SARIF log to the threshold, and publishes it through
the dedicated `artifacts:reports:sarif` type (the legacy `sast` type expects
GitLab's own JSON schema, not SARIF). It accepts `quarry_config`,
`severity_threshold` (default `low`), and `quarry_version` (default `latest`).

```yaml
include:
  - component: $CI_SERVER_FQDN/donicrosby/quarry/quarry-sast@main
    inputs:
      quarry_config: quarry.toml
      severity_threshold: high
```

GitLab ingests findings only from a **successful** job. Because the component's job
fails when findings remain, a failing scan surfaces the SARIF artifact for
inspection but does not populate the Security tab; teams that want both the native
findings and a blocking gate can gate on the artifact with a merge-request approval
policy.

### Exit-code contract

Both integrations share one contract, also usable from generic CI:

| Code | Meaning |
|---|---|
| 0 | No proven findings at or above the threshold |
| 1 | Findings at or above the threshold |
| 2 | Scan error (Quarry did not complete) |

The threshold filter itself lives in
[`ci/sarif_severity_filter.jq`](ci/sarif_severity_filter.jq) and both CI
definitions invoke that same file, so the two contracts cannot drift apart.

## Development

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pre-commit run --all-files
```

Install local hooks with:

```bash
uv run pre-commit install
uv run pre-commit install --hook-type commit-msg
```

### Browser login (opt-in)

Browser-based login (ADR-023) needs the optional `quarry[browser]` extra plus a
headless Chromium, and is exercised end-to-end against a local target by a gated
manual test. CI (no browser) skips it cleanly:

```bash
uv sync --extra browser
uv run playwright install chromium
QUARRY_BROWSER_TESTS=1 uv run pytest tests/integration/test_browser_login_e2e.py
```

The browser-capable worker image is the `quarry-dynamic` Dockerfile stage:

```bash
docker build --target quarry-dynamic -t quarry:dynamic .
```

## Deferred

- Kubernetes deployment (see `docs/kubernetes-scale-plan.md`).
