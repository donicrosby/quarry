# Dependency update policy

Quarry executes model-generated payloads by design, so anything that reaches the
build or release pipeline is part of the attack surface. This policy covers how
dependency and tooling updates are adopted. The build/release threat model lives
in [`supply-chain-threat-model.md`](supply-chain-threat-model.md).

## Minimum release age (default: 7 days)

A newly published dependency version is **not** adopted until it has been public
for **7 days**. The window gives upstream maintainers, the registry, and the
community time to catch a malicious or badly-broken release before Quarry pulls
it in.

Enforcement:

- Automated: [`.github/dependabot.yml`](../.github/dependabot.yml) sets
  `cooldown.default-days: 7` for the `uv`, `github-actions`, and `pre-commit`
  ecosystems. Dependabot will not open a version-update PR for a release that is
  younger than 7 days.
- Manual: a human bumping a version by hand (or running `uv add`/`uv lock`)
  applies the same rule — do not adopt a version published fewer than 7 days ago
  without recording an exception (below).

## Update cadence

- Dependabot checks each ecosystem **weekly** and opens grouped PRs.
- A dependency-update PR is a normal PR: it runs the full CI gate battery
  (including `uv sync --locked` / `uv lock --check` and the pinned-refs check)
  and needs review before merge.
- Pinned GitHub Actions and pre-commit hooks are updated the same way — Dependabot
  rewrites the ref as a full 40-character commit SHA, preserving the `# vN`
  comment that records the release line.

## Exceptions

The 7-day minimum age must never delay a fix for an actively exploited
vulnerability.

- **Security updates bypass the cooldown by design.** Dependabot advisories and
  `security` update PRs are not subject to `cooldown`; merge them on normal
  review.
- **Break-glass for a critical fix.** If a fix must land inside the 7-day window
  and is not covered by a security advisory, the reviewer records the exception
  in the PR description: the package, the target version, the reason the fix
  cannot wait, and the person who approved it. Approval is the repository owner
  (or a delegate named on the PR).
- **Never disable the policy globally.** Exceptions are per-package, per-PR and
  time-bounded; the `cooldown` configuration stays in place.

## Related controls

| Control | Mechanism |
| --- | --- |
| Pinned GitHub Actions / pre-commit hooks | [`scripts/check_pinned_refs.py`](../scripts/check_pinned_refs.py), run in CI (`static` job) and as a pre-commit hook |
| Locked Python deps | `uv sync --frozen` + `uv lock --check` in CI (`.github/workflows/ci.yml`) |
| Release signing + SBOM | `.github/workflows/release.yml`, verified per [`release-verification.md`](release-verification.md) |
