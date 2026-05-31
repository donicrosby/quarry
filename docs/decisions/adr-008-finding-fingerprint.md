# ADR 008: Finding Fingerprint Algorithm

## Status

Accepted

## Context

Quarry needs a way to deduplicate findings across scan reruns. If the same hardcoded secret exists in the same file at the same line, two scans of the same repo should produce the same fingerprint for that finding. This enables deduplication, regression tracking, and integration idempotency.

A bad fingerprint design would change every run (making dedup impossible) or be too coarse (merging distinct findings).

## Decision

Use a deterministic SHA-256 hash of these inputs:

- `vuln_class`: vulnerability category (e.g. "secrets", "idor")
- `file_path`: repo-relative, forward-slash normalized
- `start_line:end_line`: source span of the finding
- `key_name`: the variable, endpoint, or sink being exploited
- `evidence_kind`: what kind of evidence was found (e.g. "hardcoded_assignment")

Inputs are joined with `|` as separator and UTF-8 encoded before hashing.

Explicitly excluded from fingerprint inputs:

- scan_id (changes every run)
- timestamps (change every run)
- model output (non-deterministic)
- raw line text (fragile to whitespace changes)
- absolute local paths (machine-dependent)
- random UUIDs

## Consequences

What becomes easier:

- Deduplication across reruns is trivial: same finding = same fingerprint.
- Integration idempotency keys can incorporate the fingerprint.
- Regression tracking: a finding that disappears and reappears keeps the same fingerprint.

What becomes harder:

- If the same secret is moved to a different line, it gets a new fingerprint. This is acceptable for MVP.
- Adding new fingerprint inputs later changes existing fingerprints. Migration would be needed.

What we are explicitly not doing:

- Fuzzy deduplication (similar but not identical findings).
- Cross-file deduplication (same secret in multiple files gets separate fingerprints).
- Entropy-based fingerprinting.

## Alternatives considered

- Content-hash only: too brittle, whitespace changes break it.
- Tuple comparison without hashing: works but harder to use as idempotency keys and store.
- Including end_line in all cases: acceptable, we include it when it differs from start_line.
