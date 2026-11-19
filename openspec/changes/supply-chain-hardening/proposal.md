# Proposal: supply-chain-hardening

## Why

Quarry executes model-generated payloads by design — its build and release
integrity is a real attack surface. Today, GitHub Actions in CI and release
workflows use floating tag refs (`@v4`, `@v6`), pre-commit hooks are tag-pinned,
releases carry no cryptographic signatures and no SBOM, and the build pipeline
has no documented threat model. A compromised action or a dependency-substitution
attack could inject code into every Quarry release artifact without detection.

## What Changes

- **GitHub Actions SHA-pinning**: all action references in `.github/workflows/`
  and `.pre-commit-config.yaml` move from tag refs to commit SHAs.
- **Dependency update policy**: a minimum-release-age rule (7 days) is documented
  and enforced via Dependabot or Renovate configuration.
- **Release signing**: container images are signed with cosign, with signature
  verification instructions published.
- **SBOM generation**: each release generates a CycloneDX or SPDX SBOM capturing
  the full Python dependency tree.
- **Build/release pipeline threat model**: a documented threat model for the
  build and release pipeline covers action compromise, dependency-substitution,
  registry poisoning, and GPG/cosign key compromise.

Note: `uv lock --check` enforcement already ships in CI
(VERIFIED at b284af7:.github/workflows/ci.yml:34-36); this spec does not
re-spec it.

## Impact

- **Affected specs**: `supply-chain-hardening` (NEW capability)
- **Affected code**: `.github/workflows/ci.yml`, `.github/workflows/release.yml`,
  `.pre-commit-config.yaml`, new `.github/dependabot.yml` or `renovate.json`,
  `Taskfile.yml` (new `task sbom`, `task sign-release`), `pyproject.toml`
  (new `[project.scripts]` entries for SBOM/signing tooling if needed),
  `docs/supply-chain-threat-model.md` (new)
- **Release artifact change**: every release gains a `.sig` cosign bundle and an
  SBOM artifact alongside the container images.
- **No runtime change**: Quarry scan behavior, model calls, and agentic stages
  are unaffected.