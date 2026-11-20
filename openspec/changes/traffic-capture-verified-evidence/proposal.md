# Recording proxy funnel + hash-verified evidence store

## Why

Quarry agents (hunters, browser workers when landed) send HTTP to targets via `http_request`
(`src/quarry_tools/http_tool.py`) but there is no
total-capture layer recording what they actually sent and received. When a finding needs
proof, the only evidence is sandbox stdout/stderr — the HTTP exchanges themselves are
lost. Without a recording proxy funnel, differential-validation evidence, replay inputs
for the prompt replay harness, and SARIF/CI artifacts all lack ground truth. The
evidence that does enter the artifact store has no hash verification, no write-integrity
guarantee, and no secret-redaction.

Two prior-art systems independently converged on the same architecture: ARTEX's
traffic/ and evidence/ packages route all agent HTTP through an embedded MITM proxy
recording content-addressed full-capture with a SQLite query index, and snapshot
finding-bound exchanges into a separate hash-verified content-addressed evidence store
with writer-lock semantics so reclamation cannot race a snapshot. This change re-derives
those mechanisms cleanly for Quarry's Python/Temporal stack.

## What Changes

- **ADDED** new capability `traffic-capture-recording-proxy`: a mitmproxy sidecar
  recording all agent HTTP into a content-addressed capture store with URL-template
  normalization, SQLite query index, and host-scoped export.
- **ADDED** seven requirements to `proof-and-sandbox-execution`: evidence store
  decoupled from disposable capture, staged write with length verification,
  verify-on-read, writer-lock during snapshot, secret-redaction applied to stored
  evidence, quarantine policy, and canary-listener OOB shared surface.
- Cross-references `secret-redaction` (scrub chokepoint applied before evidence
  storage), `data-handling-and-retention` (retention lifecycle after quarantine
  release), and `prompt-injection-defense` (hostile HTTP bodies are untrusted data).
- Reconciles with in-flight wave-B lanes: B10 canary listeners
  (`spec/canary-callback-listener` @ 2a9fc6c — per-exec listener returns
  safe-field callbacks on `SandboxExecCapture.canary_callbacks`; this change
  ingests those callbacks into the capture index on the worker/activity side), B17
  proof-artifact-quarantine (t_57f46027 — quarantine policy applies to this store),
  and egress-policy-destination-sets (in-flight — sandbox-tier network-policy;
  agent-HTTP enforcement at the worker container is a deferred gap, recorded in
  task 10).

## Impact

- **`traffic-capture-recording-proxy`** (new spec) — 5 requirements, 14 scenarios.
- **`proof-and-sandbox-execution`** (extended) — +7 requirements, +18 scenarios.
  (Total: 12 requirements, 32 scenarios across both capabilities.)
- **`secret-redaction`** — referenced, no delta; `scrub` (text→text) is the chokepoint
  used by the evidence store; exchange serialization is text-safe (binary bodies
  base64-encoded).
- **`data-handling-and-retention`** — referenced, no delta; evidence artifacts released
  from quarantine enter the normal retention lifecycle.
- **`prompt-injection-defense`** — referenced, no delta; evidence ingestion treats
  hostile HTTP bodies as untrusted `<target_content>`.
- Compose stack gains one sidecar container (mitmproxy with addon); the proxy port is
  internal-network only.
- Ticket t_11ddae62 — covered.

## Non-goals

- Implementing the mitmproxy addon or evidence store in code (spec only — implementation
  in separate lane).
- Defining exact parameter-pattern regexes for URL template normalization
  (implementation detail; the four pattern CLASSES — UUID, integer, base64-token,
  ISO-date — are specified in design.md; the exact regex strings are for the implementer).
- Integrating with ClamAV for evidence (B17 malware scan hook covers that separately).
- Replacing the existing sandbox capture mechanism (HTTP capture today is a subset of
  sandbox stdout; the proxy adds a parallel full-capture layer, not a replacement).

## Design decision: mitmproxy vs thin custom recorder

Evaluated two approaches for the recording proxy:

| Criterion | mitmproxy | Thin custom recorder |
|---|---|---|
| TLS interception | Mature, audited | Need CONNECT tunnel + cert gen — ~500 LOC |
| HTTP/2 | Supported | Need h2 framing — ~300 LOC |
| Python integration | Native addon API | Native, but must build proxy loop |
| Maintenance burden | Upstream maintained | Internal maintenance forever |
| Attack surface | Well-scoped (addon sandbox) | Full proxy surface we own |
| Re-implementation risk | Low (addon, not fork) | High (full proxy from scratch) |

**Decision: mitmproxy.** The Python-native addon API gives us content-addressed blob
writing and SQLite indexing without forking or modifying mitmproxy itself. A thin
custom recorder would require reimplementing TLS interception, certificate generation,
HTTP/2 framing, and connection pooling — easily 2000+ LOC of security-critical code
with a larger attack surface. A mitmproxy addon is ~200 lines of interception and
indexing logic.

## Reconciliation against main @ b284af7

| Mechanism | Status before | What this change adds |
|---|---|---|
| Recording proxy | None | mitmproxy sidecar, content-addressed blob store, SQLite index |
| URL template dedup | None | Parameter-pattern normalization for pagination/dedup |
| Evidence hash verification | sha256 field on ArtifactRef exists but proof artifacts set it to "" | Staged write, compute-before-rename, verify-on-read |
| Evidence store decoupled from capture | None | Snapshot on finding binding, survives reclamation |
| Writer-lock during snapshot | None | Advisory lock prevents reclamation race |
| Secret-redaction on evidence | None (ARTEX stores plaintext) | scrub() before evidence storage |
| Quarantine on evidence | None | Quarantine flag applied per B17 spec |
| Canary/proxy OOB sharing | None (no proxy exists) | Same internal network surface