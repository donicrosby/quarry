# Verifying a Quarry release

Quarry release container images are signed with [cosign](https://docs.sigstore.dev/cosign/overview/)
using **keyless** signing (Sigstore). Each GitHub Release also carries a
CycloneDX SBOM and its Sigstore bundle.

No Quarry key needs to be distributed: the signature is bound to the identity of
the GitHub Actions workflow that produced it, and the signing event is recorded
in the public Sigstore transparency log (Rekor).

## Prerequisites

```bash
go install github.com/sigstore/cosign/v2/cmd/cosign@latest
# or: brew install cosign
```

## Verify a container image

Substitute the release tag (for example `1.2.3`) and the repository owner
(`donicrosby`):

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/donicrosby/quarry/\.github/workflows/release\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/donicrosby/quarry-server:1.2.3
```

The two flags that matter:

- `--certificate-identity-regexp` — pins the signature to Quarry's own release
  workflow; a signature produced by any other workflow or repository is rejected.
- `--certificate-oidc-issuer` — pins the OIDC issuer to GitHub Actions.

A successful run prints the verified signature payload. Any other result
(including a missing signature) means the image must not be trusted.

## Verify the SBOM

The release attaches `quarry-<tag>.cdx.json` (the SBOM) and
`quarry-<tag>.cdx.json.sigstore.json` (its Sigstore bundle). Download both, then:

```bash
cosign verify-blob \
  --bundle quarry-1.2.3.cdx.json.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/donicrosby/quarry/\.github/workflows/release\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  quarry-1.2.3.cdx.json
```

`Verified OK` confirms the SBOM was produced by the Quarry release workflow.

## Inspect the SBOM

```bash
python -c "import json;d=json.load(open('quarry-1.2.3.cdx.json'));print(len(d['components']),'components');print(d['metadata']['component']['name'],d['metadata']['component']['version'])"
```

The SBOM enumerates every package in the locked Python dependency tree
(`uv.lock`) with its version and provenance (PyPI `purl` + distribution hashes).
