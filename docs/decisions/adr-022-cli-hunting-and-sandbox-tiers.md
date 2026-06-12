# ADR-022: CLI hunting path — sandbox tiers, network blob artifact store, and find-side CLI-awareness

**Status:** Draft (follow-on to ADR-017; implements the deferred §5 tiers and CLI-unblocking work)  
**Date:** 2026-06-12  
**Deciders:** Quarry core team

---

## Context

ADR-017 describes three sandbox tiers (LocalSubprocess, ContainerSandbox, K8sJobSandbox) and a
network blob artifact store (Redis/S3) as future work. The prove-sandbox-subsystem branch
(ADR-017 §5/§7 cut-line) ships Tier 1 (`LocalSubprocessSandbox`) and the `ArtifactStore`
Protocol + factory with a `file://` default. This ADR governs the follow-on that delivers the
remaining tiers and makes Quarry capable of finding and proving vulnerabilities in CLI tools
(motivating target: dbt Core).

---

## Decisions

### A. Sandbox isolation tiers

**Tier 1 `LocalSubprocessSandbox`** — already shipped; POSIX rlimits, no kernel network NS on
macOS. Dev/wiring only.

**Tier 2 `ContainerSandbox`** — production default. One throwaway container per invocation,
`--network none` for CLI prove (live egress only when TargetEndpoint is threaded). Per-language
runtime image (minimal, no toolchain at prove time because build-once pre-staged the binary).
Implements `SandboxBackend` Protocol unchanged.

**Tier 3 `K8sJobSandbox`** — high-isolation / multi-tenant only. Temporal activity dispatches a
K8s Job; init-container fetches artifact refs from the blob store into an `emptyDir`; main
container runs with NetworkPolicy `--deny-all`. Reserved for hostile multi-tenant isolation;
Tier 2 is the expected production default.

**Why Tier 2 is not skipped in favour of Tier 3:** k8s is a heavy lift (Jobs + NetworkPolicy +
per-language toolchain images + cross-pod artifact transfer). `ContainerSandbox` gives real
kernel isolation with Docker/Podman already running the stack, and `--deny-all` at the container
level is operationally equivalent to NetworkPolicy for most threat models. Tier 3 is reserved for
when you genuinely need NetworkPolicy-enforced egress control in a multi-tenant cluster.

### B. Network blob artifact store — no PVC

The shared `quarry-data` volume in `docker-compose.yml` is a dev convenience that makes server +
worker implicitly co-located. For multi-pod / multi-tier sandbox, artifact passing must go through
a network blob store.

**`ArtifactStore` Protocol** (shipped in Phase 1c of the prove-sandbox branch):
- `put_bytes(key, data, *, kind, content_type, ...) -> ArtifactRef`
- `put_json(key, data, *, kind, ...) -> ArtifactRef`
- `get_bytes(artifact_ref) -> bytes`
- `get_bytes` dispatches by `ArtifactRef.uri` scheme: `file://` → `LocalArtifactStore`,
  `redis://` → `RedisArtifactStore`, `s3://` → `S3ArtifactStore`.

**`RedisArtifactStore`** (`redis://`): fast small scratch. Used for stdout/stderr captures,
JSON artifacts, `input_files`, small corpora. Redis values are in-memory — **never store
large binaries or corpora here** (multi-MB compiled binary → S3).

**`S3ArtifactStore`** (`s3://`): large blobs. Used for compiled release binaries and tar'd
corpora. `botocore` is already a dependency.

**Size/kind router in `build_artifact_store()` factory:** `put_bytes` inspects `size_bytes` and
`ArtifactKind` — binary/large kinds → S3, everything else → Redis (prod) or `file://` (dev).
Controlled by `QUARRY_ARTIFACT_BACKEND` / `QUARRY_REDIS_URL` / `QUARRY_S3_BUCKET`.

### C. Find-side CLI-awareness

For Quarry to *find* (not just prove) CLI vulnerabilities, the find side needs:

1. **`BuildCommand` population:** `recon_synthesis.py` currently hardcodes `build_commands=[]`.
   Recon must discover and emit build/run commands (cargo, pip, npm). `repo_type=="cli"` is
   already inferred from `cli_arg`/`main` entry-point kinds.

2. **CLI invocation metadata on `EntryPoint`:** `EntryPoint.kind` already includes `cli_arg` and
   `main`, but the schema has no `invocation` (command + argv template) or
   `attacker_controlled_input` (which arg/stdin/config file is injectable). Add these optional
   fields so the prove agent knows *how to call* the binary and *where to inject*.

3. **CLI-oriented hunters:** existing hunters are HTTP-route-oriented. New hunters target:
   argv parsing (`clap`, `argparse`, `cobra`), `subprocess`/`Command` sinks, config-file parsing,
   path traversal from config-specified paths, deserialization of user-controlled input.

### D. Build-once for real tools

The sandboxed build-once primitive (shipped in Phase 4b of the prove-sandbox branch) is designed
to generalize. For dbt Core:
- `cargo build --release` runs inside `LocalSubprocessSandbox`/`ContainerSandbox`.
- Binary artifact captured to S3 via `S3ArtifactStore`.
- `ProveCorpus.source` = a git URL of a real dbt project; materialized into sandbox working dir.
- `input_files` = a crafted `dbt_project.yml` or model file that triggers the vulnerability.

---

## Consequences

- Every sandbox tier + artifact backend change is a backend drop-in against the shipped Protocols.
  No workflow/agent/PROVE stage code changes.
- Removing the shared `quarry-data` volume (after Redis/S3 are live) is the explicit end-state;
  until then `file://` + the named volume is the dev default.
- CLI hunting requires find-side (C) and prove-side (A, B, D) work to be in sync; the follow-on
  branch (`feat/cli-hunting-path`) delivers them together.
- For the dbt Core demo specifically: a real dbt-project corpus + sandboxed build produces a
  `ProofArtifact(proof_type="cli_exec")` with evidence that a crafted `dbt_project.yml` triggered
  arbitrary code execution through dbt's model-loading / hook execution path.

---

## References

- ADR-017: `docs/decisions/adr-017-live-dynamic-validation.md` §5 (sandbox model) and §7 (proof capture)
- ADR-018: `docs/decisions/adr-018-target-auth-credentials.md`
- Prove-sandbox implementation: `feat/prove-sandbox-subsystem` branch
