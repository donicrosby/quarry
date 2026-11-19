# supply-chain-hardening Delta

## ADDED Requirements

### Requirement: GitHub Actions pinned to commit SHAs

All GitHub Actions in `.github/workflows/` SHALL reference a full commit SHA, not
a tag or branch ref. CI SHALL fail when any action reference is not a 40-character
hex SHA. Dependabot SHALL be configured to auto-update pinned SHAs.

#### Scenario: unpinned-action-blocks-ci

- **WHEN** a pull request introduces, in any workflow file under `.github/workflows/`, an action reference that is not a 40-character commit SHA
- **THEN** CI fails with a message naming the unpinned action and the required format

#### Scenario: pinned-actions-pass-ci

- **WHEN** all action references in `.github/workflows/` are commit SHAs
- **THEN** CI passes the action-pinning check

#### Scenario: dependabot-updates-pinned-action-shas

- **WHEN** Dependabot evaluates the repository's GitHub Actions update group
- **THEN** it opens PRs bumping pinned action SHAs to newer commits, keeping every `uses:` ref a full 40-character SHA

### Requirement: Pre-commit hooks pinned to commit SHAs

Every `repo` entry in `.pre-commit-config.yaml` that references a remote repository
SHALL pin its `rev` to a commit SHA, not a tag. Local hooks (language: system) are
exempt because they execute from the working tree.

#### Scenario: tag-pinned-pre-commit-hook-blocked

- **WHEN** a remote hook `rev:` in `.pre-commit-config.yaml` is a tag (e.g. `v2.12.1b3`)
- **THEN** a CI check or pre-commit hook fails naming the hook and requiring a SHA

#### Scenario: sha-pinned-hooks-accepted

- **WHEN** all remote pre-commit hook revisions are commit SHAs
- **THEN** the check passes

### Requirement: Dependency update policy with minimum release age

A documented dependency update policy SHALL require a minimum release age before
adopting new dependency versions (default 7 days). The policy SHALL be automated
via Dependabot or Renovate configuration checked into the repository.

#### Scenario: dependabot-config-enforces-minimum-age

- **WHEN** a dependency has a new version published fewer than 7 days ago
- **THEN** Dependabot does not open an update PR for that version until the age threshold is met

#### Scenario: update-automation-config-checked-in

- **WHEN** the repository is inspected for dependency update automation
- **THEN** a `.github/dependabot.yml` (or `renovate.json`) is checked in, configuring a minimum release age of 7 days for Python (uv) dependencies and auto-updates for pinned GitHub Actions SHAs

#### Scenario: policy-documented-in-repo

- **WHEN** the repository is inspected for the dependency update policy
- **THEN** `docs/dependency-policy.md` exists and states the minimum release age (default 7 days), update cadence, and exception process

### Requirement: Release artifacts are cryptographically signed

Every container image published as a Quarry release SHALL be signed with cosign
keyless signing (Sigstore). The release workflow SHALL publish signature
verification instructions alongside the release notes.

#### Scenario: unsigned-image-release-blocked

- **WHEN** the release workflow attempts to publish a container image without a valid cosign signature
- **THEN** the release step fails before the GitHub Release is created

#### Scenario: signatures-verifiable-by-end-users

- **WHEN** an end user pulls a signed Quarry container image
- **THEN** they can verify the signature with `cosign verify` using the public transparency log

### Requirement: SBOM generated per release

Each release SHALL generate a Software Bill of Materials (SBOM) in CycloneDX or
SPDX format capturing the complete Python dependency tree. The SBOM SHALL be
published as a release artifact alongside the container images.

#### Scenario: verification-instructions-published

- **WHEN** a release is published
- **THEN** the release notes or `docs/release-verification.md` carry a `cosign verify` command including the required identity and OIDC issuer flags

#### Scenario: sbom-attached-to-github-release

- **WHEN** a release tag is pushed
- **THEN** an SBOM artifact is generated and attached to the GitHub Release

#### Scenario: sbom-covers-full-dependency-tree

- **WHEN** the SBOM is inspected
- **THEN** it enumerates every Python package in the locked dependency tree with its version and provenance

### Requirement: Build and release pipeline threat model documented

A threat model for the build and release pipeline SHALL be documented in the
repository. It SHALL cover at minimum: action compromise via unpinned refs,
dependency-substitution attacks, container registry poisoning, and signing key
compromise, with mitigations for each.

#### Scenario: threat-model-exists-in-docs

- **WHEN** a contributor or auditor reviews the repository
- **THEN** `docs/supply-chain-threat-model.md` exists and covers the four required threat classes

#### Scenario: threat-model-mitigations-are-actionable

- **WHEN** a threat class is described
- **THEN** the corresponding mitigation is implemented or explicitly noted as deferred with a tracking reference