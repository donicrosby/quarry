# Proof artifact quarantine policy (D6)

## Why

Proof artifacts — sandbox stdout/stderr, HTTP captures, and future binary outputs
(core dumps, compiled PoCs, generated files) — are attacker-controlled content. Today
they enter the artifact store with no quarantine marking, no hash recording, no size
classification, and no malware scan hook. An operator cannot distinguish a harmless
code snippet from a working exploit payload; a downstream integration cannot gate on
safety. This change adds a quarantine policy that marks, hashes, size-gates, and
optionally scans every proof artifact before it is accepted.

## What Changes

- **ADDED** four requirements under `proof-and-sandbox-execution`: quarantine marking,
  safety properties (hash, no-exec, size limits), local-only-by-default storage, and a
  malware scan hook.
- Cross-references `data-handling-and-retention` (quarantined artifacts survive deletion
  sweeps equivalent to held data) and `persistence-and-artifact-store` (quarantine
  extends the local-only guard already enforced for full prompt storage).

## Impact

- **`proof-and-sandbox-execution`** — new quarantine requirements (this change).
- **`data-handling-and-retention`** — quarantined artifacts are exempt from routine
  retention sweeps; release from quarantine re-enters normal retention lifecycle.
  No delta needed: the "Held scan survives a sweep" scenario (spec.md:47-50)
  establishes the sweep-exemption pattern at scan level; this change pins the
  artifact-level exemption via its own `quarantined-artifact-survives-sweep`
  scenario.
- **`persistence-and-artifact-store`** — the artifact store's local-only guard (already
  enforced for full prompts via `store_prompt` fail-closed) is extended to proof
  artifacts by the quarantine requirements. No spec delta needed; the code reuse is an
  implementation concern.
- **`secret-redaction`** — scrubbing already runs on sandbox output before storage
  (sandbox_exec.py:210-211). Quarantine adds an integrity layer, not a redaction change.
- Ticket `t_57f46027` (D6) — covered; blocks C5 (fuzzing produces crashes).

## Non-goals

- Implementing ClamAV integration (spec hook only; opt-in deployment decision).
- Defining exact byte limits per `ArtifactKind` (deployment-configurable; the spec
  requires the enforcement mechanism, not the numbers).
- Changing the exploit workflow's artifact handling (same quarantine policy applies;
  spec is written generically over "proof artifact" to cover both prove and exploit
  outputs).

## Reconciliation against main @ b284af7

Original ticket (2026-09-10) wrote against a pre-Lane-A tree. After ~45 merges:

| Ticket item | Status | Notes |
|---|---|---|
| Never mark executable | KEPT | No exec-bit clearing exists; spec requires it for binary artifacts |
| Hash-recorded | KEPT | `ArtifactRef.sha256` field exists (schemas.py:418) but proof artifacts set it to `""` (run_scan.py:3807); reports DO hash (run_scan.py:4048) — the gap is proof-specific |
| Local-only by default | KEPT | Local-only guard exists for prompts (`_LOCAL_BACKENDS` guard in store.py:176-184) but NOT for proof artifacts |
| Size limits per artifact kind | KEPT | Only sandbox stdout/stderr has a 10KB cap (sandbox_exec.py:44); no kind-level enforcement |
| Malware scan hook | KEPT | Zero trace in codebase |
| Extend data-handling-and-retention | DROPPED from delta | Existing "Held scan survives a sweep" scenario already covers retention-exemption pattern; no spec change needed |
| Extend persistence-and-artifact-store | DROPPED from delta | Local-only guard already exists for prompts; quarantine extends it without a spec change to the artifact-store capability |