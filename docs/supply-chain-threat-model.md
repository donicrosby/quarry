# Build & release pipeline threat model

Scope: the machinery that turns a commit in this repository into a released
Quarry container image and GitHub Release. It does **not** cover Quarry's runtime
scanning behavior (see `docs/architecture.md`).

Why this matters here specifically: Quarry executes model-generated payloads by
design, and it is shipped as the reference implementation for safe agentic
testing. A build/release compromise therefore reaches every downstream user, and
would poison the tool whose entire pitch is supply-chain hygiene.

## Assets

- The published container images (`ghcr.io/<owner>/quarry-server`,
  `quarry-worker`).
- The GitHub Release artifacts (SBOM, notes).
- The CI/release workflow definitions themselves and the secrets they can reach
  (`GITHUB_TOKEN`, GHCR push rights, the OIDC identity).

## Trust boundaries

1. **Upstream → CI**: third-party GitHub Actions and pre-commit hooks are
   executable code pulled in by the workflow. Everything they can reach is
   inside the build trust boundary.
2. **PyPI/registries → build**: the locked Python dependency tree.
3. **CI → GHCR**: the image push, authenticated by a short-lived `GITHUB_TOKEN`.
4. **GHCR/Release → user**: what a user downloads and runs.

## Threat classes and mitigations

### 1. Action compromise via unpinned refs

A tag such as `uses: actions/checkout@v4` is mutable: the upstream repository
can re-point it at different code at any time, and nothing in Quarry's history
records that the executed code changed. A compromised or malicious action then
runs with CI's privileges.

- **Mitigation**: every `uses:` reference in `.github/workflows/` is pinned to a
  full 40-character commit SHA, and every remote pre-commit hook `rev:` in
  `.pre-commit-config.yaml` is a commit SHA.
- **Enforcing mechanism**: `scripts/check_pinned_refs.py` (fails the CI `static`
  job and runs as the `pinned-refs` pre-commit hook) plus Dependabot's
  `github-actions` / `pre-commit` update groups, which move the pins forward as
  full SHAs.

### 2. Dependency substitution

An attacker publishes a malicious release of a dependency Quarry resolves (or
takes over a package). If Quarry adopts it immediately, the payload can execute
in the build (via build hooks) and in the shipped image.

- **Mitigation**: the Python dependency tree is locked (`uv.lock`) and CI
  installs with `uv sync --...--frozen`; `uv lock --check` fails CI if the lock
  drifts from `pyproject.toml`. New versions are adopted only after a **7-day
  minimum release age**.
- **Enforcing mechanism**: `.github/workflows/ci.yml` (`uv sync --frozen`,
  `uv lock --check`) and [`.github/dependabot.yml`](../.github/dependabot.yml)
  `cooldown.default-days: 7`; policy narrated in
  [`dependency-policy.md`](dependency-policy.md).

### 3. Container registry poisoning

An attacker with push access to GHCR (or a MITM on the pull path) replaces an
image the user believes came from Quarry.

- **Mitigation**: releases are signed and the signature is bound to the exact
  image **digest** (immutable), so a swapped image fails verification. Users
  verify with `cosign verify` before running.
- **Enforcing mechanism**: the `Sign container images` step in
  `.github/workflows/release.yml` signs
  `ghcr.io/<owner>/<image>@<digest>`; verification instructions in
  [`release-verification.md`](release-verification.md).

### 4. Signing-identity / transparency-log compromise

The signing key/model here is **keyless**: there is no long-lived Quarry signing
key to steal. The relevant compromise classes are therefore (a) takeover of the
GitHub Actions OIDC identity used to sign, or (b) tampering with the Sigstore
transparency log (Rekor). Long-lived-key compromise does not apply.

- **Mitigation**: keyless signing uses a short-lived certificate minted from the
  workflow's OIDC identity (`id-token: write` on the release job only), and every
  signature is recorded in Rekor. Verification pins both the certificate
  identity (this repository's `release.yml`) and the OIDC issuer
  (`token.actions.githubusercontent.com`), so a signature from any other
  workflow or identity is rejected.
- **Enforcing mechanism**: `permissions: id-token: write` scoped to the `release`
  job in `.github/workflows/release.yml`; the `--certificate-identity-regexp` /
  `--certificate-oidc-issuer` flags in
  [`release-verification.md`](release-verification.md).

## Residual risk & deferred items

- Keyless signatures protect *what was built by this workflow*; they do not
  attest that the source tree itself is uncompromised. GitHub-hosted runner and
  repository-integrity trust remain.
- The SBOM describes the locked Python tree; it does not yet enumerate OS
  packages in the image base layer. An image-level scanner (for example syft on
  the built image) is a candidate follow-up.
- Enforcing the 7-day window at the resolver level (for example
  `[tool.uv] exclude-newer`) is deliberately not enabled, because a relative
  window makes locked resolution time-dependent; the bot-side `cooldown` plus the
  documented manual rule are the current enforcement.
