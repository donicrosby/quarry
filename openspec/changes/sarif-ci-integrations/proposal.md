# Change: sarif-ci-integrations

## Why

Quarry produces findings but has no machine-readable export for CI/CD toolchains.
SARIF 2.1.0 (OASIS Standard) is the universal interchange format consumed by GitHub
Code Scanning, GitLab SAST, and other static-analysis dashboards. Without SARIF export,
Quarry scans run in isolation — findings never surface in the developer's existing
code-review workflow. A reusable GitHub Action and a GitLab CI/CD component lower the
adoption bar: one workflow line to run Quarry and see results in the native security
tab.

## What Changes

- **SARIF 2.1.0 export as a FindingSink**: A new plugin in `quarry_integrations/sinks/`
  that converts `FinalFinding` records into a SARIF v2.1.0 log file. Maps Quarry
  severity to SARIF levels, finding fingerprints to SARIF `partialFingerprints`, and
  source locations to SARIF `physicalLocation` entries. Respects the existing
  idempotency, dry-run, and redaction guardrails inherited from the FindingSink
  protocol.
- **Reusable GitHub Action**: A composite or reusable workflow action
  (`action.yml` / `.github/workflows/quarry-scan.yml`) that runs Quarry against a
  repository, collects the SARIF output, and uploads it via
  `github/codeql-action/upload-sarif`. Inputs: quarry config, target repo, optional
  severity threshold.
- **GitLab CI/CD component**: A GitLab component (`templates/quarry-sast.yml`) that
  runs Quarry in a GitLab pipeline, produces a SARIF artifact, and publishes it for
  GitLab SAST consumption. Inputs mirror the GitHub Action.

## Impact

- **Specs**: `integrations-and-event-sinks` (ADDED three requirements: SARIF export
  sink, GitHub Action contract, GitLab component contract).
- **Code**: `src/quarry_integrations/sinks/sarif.py` (new FindingSink),
  `action.yml` or `.github/workflows/quarry-scan.yml` (reusable action),
  `templates/quarry-sast.yml` (GitLab component), pyproject.toml entry for the new
  sink plugin.
- **Threat model**: SARIF export is a read-only serialization of findings that were
  already persisted — it introduces no new trust boundary. The GitHub Action and
  GitLab component run Quarry in a CI context where the scanned code is already
  trusted by the CI runner; they do not escalate privileges beyond what the CI job
  already has. The SARIF upload step sends findings to the platform's code-scanning
  API; no secrets or raw target contents are embedded in the SARIF log.
- **Non-goals**: A standalone CLI `quarry sarif` subcommand (the SARIF export is a
  sink, invoked through the normal scan-completion delivery path); OWASP ASVS or
  CWE mapping (findings carry Quarry's own class taxonomy — mapping to external
  taxonomies is deferred); SARIF results management (suppression, baselining —
  handled by the consuming platform, not Quarry); a Docker image for standalone CI
  (the GitHub Action and GitLab component already provide the execution
  environment).

## Reconcile notes (2026-09-10 original vs b284af7 main)

- **Kept**: SARIF 2.1.0 export, GitHub Action, GitLab component. Core need unchanged
  and B0 backlog recon classified as VALID (substance genuinely absent from main).
- **Dropped**: "GitHub App or OAuth app for PR annotations" — GitHub Code Scanning
  already surfaces SARIF results in PRs via the `upload-sarif` action; no custom
  integration needed. "Webhook-based delivery pipeline" — the existing FindingSink
  protocol with idempotency and dry-run (VERIFIED at
  b284af7:src/quarry_integrations/base.py:21-42) already handles delivery lifecycle;
  SARIF is a serialization format, not a new delivery mechanism. "SLSA provenance
  claims" — separate concern covered by the `provenance-and-manifest` spec.
  "GitLab Ultimate-specific features" — the component targets GitLab SAST which is
  available on all tiers (Free and above).
- **Rescoped**: SARIF export is a FindingSink plugin (VERIFIED protocol at
  b284af7:src/quarry/plugin_types.py:35-38), not a standalone exporter — this
  reuses the existing plugin registry, idempotency keying, dry-run flag, and
  redaction pipeline rather than duplicating them. The GitHub Action is a reusable
  workflow (building on the existing CI workflow patterns VERIFIED at
  b284af7:.github/workflows/ci.yml) rather than a Docker-based action — this
  keeps the action transparent (users can inspect the workflow) and avoids Docker
  image maintenance burden.