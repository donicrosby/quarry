# Tasks: sarif-ci-integrations

## 1. SARIF 2.1.0 model
- [ ] 1.1 Define Pydantic models for SARIF v2.1.0 log structure in `src/quarry_integrations/sarif_models.py`: `SarifLog`, `Run`, `Tool`, `Driver`, `Result`, `Location`, `PhysicalLocation`, `ArtifactLocation`, `Region`, `ReportingDescriptor` (ASSERT: models round-trip through `model_dump_json()` and match the SARIF 2.1.0 JSON Schema — coder must validate against the published schema)
- [ ] 1.2 Define the severity-to-level mapping (`critical`→`error`, `high`→`error`, `medium`→`warning`, `low`/`info`→`note`) as a constant lookup table
- [ ] 1.3 Define the finding-to-SARIF-result conversion function: `finding_to_sarif_result(finding: FinalFinding) -> Result` mapping severity, fingerprint, source locations, message text, and rule metadata

## 2. SARIF FindingSink plugin
- [ ] 2.1 Implement `SarifSink` class in `src/quarry_integrations/sinks/sarif.py` implementing the FindingSink protocol (VERIFIED at b284af7:src/quarry/plugin_types.py:35-38): `name = "sarif"`, `plugin_type = PluginType.FINDING_SINK`, `deliver()` method
- [ ] 2.2 `deliver()` collects all findings from the scan into a single SARIF log per invocation (ASSERT: one `Run` per scan with the scan's metadata as `invocation` — coder must verify `FinalFinding.scan_id` provides sufficient invocation detail)
- [ ] 2.3 Wire the SARIF sink into the plugin registry (`pyproject.toml` `[project.entry-points."quarry.finding_sink"]`) following the existing FileSink/JiraDryRunSink/SlackDryRunSink pattern
- [ ] 2.4 Idempotency: use `build_idempotency_key()` (VERIFIED at b284af7:src/quarry_integrations/base.py:21-22) so a re-run does not produce duplicate SARIF artifacts
- [ ] 2.5 Dry-run: when `ctx.dry_run` is True, return a DRY_RUN IntegrationRun and write no SARIF file

## 3. SARIF output artifact
- [ ] 3.1 Write the complete SARIF log as a single JSON file via `ctx.artifact_store.put_json()` with `kind=ArtifactKind.INTEGRATION_PAYLOAD` (VERIFIED pattern at b284af7:src/quarry_integrations/sinks/file_sink.py:33-37)
- [ ] 3.2 The artifact file name SHALL be `sarif/<scan_id>.sarif.json` so CI runners can discover it with a glob
- [ ] 3.3 RED: test that an empty scan (zero findings) produces a valid SARIF log with empty `results[]` and correct `tool.driver` metadata

## 4. Reusable GitHub Action
- [ ] 4.1 Create `.github/workflows/quarry-scan.yml` as a reusable workflow (`workflow_call` trigger) with inputs: `quarry_config` (string, required), `target_repo` (string, default `${{ github.workspace }}`), `severity_threshold` (string, default `low`), `quarry_version` (string, default `latest`)
- [ ] 4.2 Workflow steps: checkout target repo → install Quarry (uv/pip per quarry_version) → run quarry scan with config → locate SARIF artifact → upload via `github/codeql-action/upload-sarif@v3`
- [ ] 4.3 The `upload-sarif` step SHALL reference the SARIF artifact path as `sarif/*.sarif.json`
- [ ] 4.4 RED: test that a scan failure (non-zero quarry exit) causes the workflow to fail without attempting upload
- [ ] 4.5 Add a `README.md` section or `action.yml` metadata documenting the action inputs and an example caller workflow snippet

## 5. GitLab CI/CD component
- [ ] 5.1 Create `templates/quarry-sast.yml` as a GitLab CI/CD component with `spec:` block declaring inputs: `quarry_config` (string), `severity_threshold` (string, default `low`), `quarry_version` (string, default `latest`)
- [ ] 5.2 Component job: `quarry-sast` stage runs Quarry scan, collects SARIF output, publishes as `artifacts:reports:sast` with path `sarif/*.sarif.json` (ASSERT: GitLab SAST expects the `sast` report type with SARIF format — coder must verify against current GitLab SAST documentation)
- [ ] 5.3 The component SHALL use the `$CI_PROJECT_DIR` as the default target repository
- [ ] 5.4 RED: test that a scan failure causes the job to fail without producing a SAST artifact
- [ ] 5.5 Add a `README.md` section documenting the component inputs and an example `.gitlab-ci.yml` include snippet

## 6. Verification
- [ ] 6.1 Unit test: `finding_to_sarif_result()` produces correct SARIF result shape for a FinalFinding with all fields populated
- [ ] 6.2 Unit test: severity-to-level mapping covers all Quarry severity values
- [ ] 6.3 Unit test: empty findings list produces valid SARIF log with empty results
- [ ] 6.4 Unit test: SARIF log round-trips through Pydantic model_dump_json and matches fixture
- [ ] 6.5 Unit test: SarifSink with dry_run=True returns DRY_RUN and writes no file
- [ ] 6.6 Integration test: end-to-end scan with SARIF sink produces a valid .sarif.json file at the expected artifact path
- [ ] 6.7 Validate the GitHub Action reusable workflow YAML syntax with `actionlint` or GitHub's schema validator
- [ ] 6.8 Validate the GitLab component YAML syntax with `gitlab-ci-lint` or equivalent
- [ ] 6.9 Ruff + pyright (strict) + vulture clean on all new code

## 7. Landing
- [ ] 7.1 Conventional commit on this branch, `openspec validate sarif-ci-integrations --strict` green, push
- [ ] 7.2 CI green (existing test suite + new SARIF tests)
- [ ] 7.3 Manual smoke test: run a local scan with the SARIF sink enabled, verify the output .sarif.json opens in a SARIF viewer or passes `sarif-tools info` validation