# supply-chain-hardening Tasks

## 1. Pin GitHub Actions to commit SHAs

- [ ] 1.1 Replace every `uses:` tag ref in `.github/workflows/ci.yml` with the commit SHA its current tag resolves to
- [ ] 1.2 Replace every `uses:` tag ref in `.github/workflows/release.yml` with the commit SHA its current tag resolves to
- [ ] 1.3 Add a CI step (or pre-commit hook) that fails when any `uses:` value is not a 40-char hex SHA
- [ ] 1.4 Re-run CI to confirm the pinning check passes on the pinned workflows

## 2. Pin pre-commit hooks to commit SHAs

- [ ] 2.1 Replace each `rev:` tag in `.pre-commit-config.yaml` remote repos with the commit SHA the tag currently resolves to
- [ ] 2.2 Add a CI check or hook that validates all remote `rev:` values are commit SHAs
- [ ] 2.3 Run `pre-commit run --all-files` to confirm hooks still execute correctly

## 3. Dependency update policy

- [ ] 3.1 Add `.github/dependabot.yml` (or `renovate.json`) with `minimum-release-age: 7 days` for pip/uv deps
- [ ] 3.2 Add the same SHA-pin auto-update group to the dependabot/renovate config for GitHub Actions
- [ ] 3.3 Document the policy in `docs/dependency-policy.md`: minimum age, update cadence, exception process

## 4. Release signing (cosign)

- [ ] 4.1 Add `cosign sign` step to `.github/workflows/release.yml` after image push, using keyless signing
- [ ] 4.2 Grant `id-token: write` permission to the release job for Sigstore OIDC
- [ ] 4.3 Add `cosign verify` instructions to the release notes or `docs/release-verification.md`
- [ ] 4.4 Test with a dry-run release (tag a pre-release) to confirm signing works end-to-end

## 5. SBOM generation per release

- [ ] 5.1 Add SBOM generation step to `.github/workflows/release.yml` (e.g. `uv export --format requirements.txt` piped to `syft`, or `pip-audit` / `cyclonedx-bom`)
- [ ] 5.2 Attach the generated SBOM as a release artifact (upload to the GitHub Release)
- [ ] 5.3 Verify the SBOM covers the full locked dependency tree from `uv.lock`

## 6. Build/release pipeline threat model

- [ ] 6.1 Write `docs/supply-chain-threat-model.md` covering: action compromise (unpinned refs), dependency substitution, registry poisoning, signing key compromise
- [ ] 6.2 For each threat class, state the mitigation and link to the enforcing mechanism (CI check, policy doc, workflow step)
- [ ] 6.3 Cross-reference with `docs/architecture.md` Deferred section (remove "Signed provenance / SBOM" line)

## 7. Verification

- [ ] 7.1 `npx openspec validate supply-chain-hardening --strict` exits 0
- [ ] 7.2 CI passes on the branch with all pinned SHAs and new checks
- [ ] 7.3 Dry-run release: images are signed, SBOM is attached, verification instructions work