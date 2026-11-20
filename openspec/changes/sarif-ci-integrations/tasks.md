# Tasks: sarif-ci-integrations

## 1. SARIF 2.1.0 model
- [ ] 1.1 Define Pydantic models for SARIF v2.1.0 log structure in `src/quarry_integrations/sarif_models.py`: `SarifLog`, `Run`, `Tool`, `Driver`, `Result`, `Location`, `PhysicalLocation`, `ArtifactLocation`, `Region`, `ReportingDescriptor` (ASSERT: models round-trip through `model_dump_json()` and match the SARIF 2.1.0 JSON Schema — coder must validate against the published schema)
- [ ] 1.2 Define the severity-to-level mapping (`critical`→`error`, `high`→`error`, `medium`→`warning`, `low`/`info`→`note`) as a constant lookup table
- [ ] 1.3 Define the finding-to-SARIF-result conversion function: `finding_to_sarif_result(finding: FinalFinding) -> Result` mapping severity, fingerprint, source locations, message text, and rule metadata; also carry the original Quarry severity in `result.properties.quarry.severity` so CI-side `severity_threshold` filtering can act on the pre-mapping value (the severity→level mapping collapses `low`/`info`)

## 2. SARIF FindingSink plugin
- [ ] 2.1 Implement `SarifSink` class in `src/quarry_integrations/sinks/sarif.py` implementing the FindingSink protocol (VERIFIED at b284af7:src/quarry/plugin_types.py:35-38): `name = "sarif"`, `plugin_type = PluginType.FINDING_SINK`, `deliver()` method
- [ ] 2.2 `deliver()` merges its single finding into the per-scan SARIF log at `sarif/<scan_id>.sarif.json` (read-modify-write: first call creates the log with `tool.driver` metadata, later calls append their `Result`). The FindingSink protocol delivers ONE finding per call (VERIFIED at b284af7:src/quarry_activities/integrations.py:48), so scan-level accumulation happens across calls; one `IntegrationRun` per finding, matching FileSink
- [ ] 2.3 Wire the SARIF sink into the plugin registry under `[project.entry-points."quarry.plugins"]` with key `sarif`, following the existing file/jira_dry_run/slack_dry_run registrations (VERIFIED pattern at b284af7:pyproject.toml:54-59); the unified loader (`quarry_plugins.registry.load_plugins`) dispatches by the `plugin_type = PluginType.FINDING_SINK` class attribute — there is no per-type entry-point group
- [ ] 2.4 Idempotency: use `build_idempotency_key()` (VERIFIED at b284af7:src/quarry_integrations/base.py:21-22) so a re-run does not produce duplicate SARIF artifacts
- [ ] 2.5 Dry-run: when `ctx.dry_run` is True, return a DRY_RUN `IntegrationRun` and write the dry-run SARIF payload artifact (JiraDryRunSink/SlackDryRunSink precedent at b284af7: dry-run writes a payload artifact, never an external side effect)

## 3. SARIF output artifact
- [ ] 3.1 Write the complete SARIF log as a single JSON file via `ctx.artifact_store.put_json()` with `kind=ArtifactKind.INTEGRATION_PAYLOAD` (VERIFIED pattern at b284af7:src/quarry_integrations/sinks/file_sink.py:33-37)
- [ ] 3.2 The artifact file name SHALL be `sarif/<scan_id>.sarif.json` so CI runners can discover it with a glob
- [ ] 3.3 RED: test that an empty scan (zero findings) produces a valid SARIF log with empty `results[]` and correct `tool.driver` metadata

## 4. Reusable GitHub Action
- [ ] 4.1 Create `.github/workflows/quarry-scan.yml` as a reusable workflow (`workflow_call` trigger) with inputs: `quarry_config` (string, required), `target_repo` (string, default `${{ github.workspace }}`), `severity_threshold` (string, default `low`), `quarry_version` (string, default `latest`)
- [ ] 4.2 Workflow steps: checkout target repo → checkout Quarry at ref `quarry_version` and install with `pip install .` (Quarry is not on PyPI — `pip install quarry` resolves an unrelated package) → run quarry scan with config → apply `severity_threshold` to `runs[0].results[]` via jq against `properties.quarry.severity` (keep rank ≥ threshold) → locate SARIF artifact → upload via `github/codeql-action/upload-sarif@v3`; job declares `permissions: security-events: write` (required by upload-sarif)
- [ ] 4.3 The `upload-sarif` step SHALL set `sarif_file` to the `sarif/` directory and `category: quarry` (upload-sarif accepts a file or directory, not a glob pattern; a directory upload merges every SARIF file within, and the category namespaces the results)
- [ ] 4.4 RED: test that a scan failure (non-zero quarry exit) causes the workflow to fail without attempting upload
- [ ] 4.5 Add a `README.md` section documenting the reusable workflow inputs and an example caller workflow snippet (4.1 pins the reusable-workflow shape via `workflow_call`; no `action.yml`)
- [ ] 4.6 RED: test that the `severity_threshold` jq filter drops results below the threshold from the uploaded log (fixture SARIF log with mixed severities, filter per 4.2, assert remaining severity set)

## 5. GitLab CI/CD component
- [ ] 5.1 Create `templates/quarry-sast.yml` as a GitLab CI/CD component with `spec:` block declaring inputs: `quarry_config` (string), `severity_threshold` (string, default `low`), `quarry_version` (string, default `latest`)
- [ ] 5.2 Component job: `quarry-sast` stage installs Quarry per 4.2, runs the scan, applies the `severity_threshold` jq filter per 4.2, and publishes as `artifacts:reports:sarif` with path `sarif/*.sarif.json` (ASSERT verified 2026-11 against docs.gitlab.com: SARIF 2.1.0 goes under the dedicated `artifacts:reports:sarif` report type; the legacy `sast` type expects GitLab's own JSON schema, not SARIF — findings ingest into the Security tab only when the job succeeds)
- [ ] 5.3 The component SHALL use the `$CI_PROJECT_DIR` as the default target repository
- [ ] 5.4 RED: test that a scan failure causes the job to fail without findings being ingestable by GitLab (job fails; per 5.2 ingestion requires job success)
- [ ] 5.5 Add a `README.md` section documenting the component inputs and an example `.gitlab-ci.yml` include snippet
- [ ] 5.6 RED: test that the `severity_threshold` jq filter drops results below the threshold from the published `reports:sarif` artifact (fixture per 4.6)

## 6. Verification
- [ ] 6.1 Unit test: `finding_to_sarif_result()` produces correct SARIF result shape for a FinalFinding with all fields populated
- [ ] 6.2 Unit test: severity-to-level mapping covers all Quarry severity values
- [ ] 6.3 Unit test: empty findings list produces valid SARIF log with empty results
- [ ] 6.4 Unit test: SARIF log round-trips through Pydantic model_dump_json and matches fixture
- [ ] 6.5 Unit test: SarifSink with dry_run=True returns DRY_RUN and writes the dry-run payload artifact
- [ ] 6.6 Integration test: end-to-end scan with SARIF sink produces a valid .sarif.json file at the expected artifact path
- [ ] 6.7 Validate the GitHub Action reusable workflow YAML syntax with `actionlint` or GitHub's schema validator
- [ ] 6.8 Validate the GitLab component YAML syntax with `gitlab-ci-lint` or equivalent
- [ ] 6.9 Ruff + pyright (strict) + vulture clean on all new code
- [ ] 6.10 RED: test that the SARIF result serializes only mapped finding fields — non-mapped fields (`proof_artifact_ids`, `trace_id`, raw evidence refs) never appear in the log (capability requirement: redaction before egress and no secret passing)

## 7. Landing
- [ ] 7.1 Conventional commit on this branch, `openspec validate sarif-ci-integrations --strict` green, push
- [ ] 7.2 CI green (existing test suite + new SARIF tests)
- [ ] 7.3 Manual smoke test: run a local scan with the SARIF sink enabled, verify the output .sarif.json opens in a SARIF viewer or passes `sarif-tools info` validation