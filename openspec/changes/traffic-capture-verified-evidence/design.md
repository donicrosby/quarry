# Design notes — traffic-capture-verified-evidence

## Architecture overview

```text
  ┌──────────────────────────────────────────────────────────────────────────┐
  │                          Compose stack (internal network)                 │
  │                                                                          │
  │  ┌─────────┐   ┌──────────┐   ┌─────────────────────┐                   │
  │  │ Worker  │   │ Browser  │   │  Sandbox-Exec       │                   │
  │  │ container│   │ Worker   │   │  Activity           │                   │
  │  │         │   │ (planned)│   │                     │                   │
  │  │ HTTP_   │   │ HTTP_    │   │  B10 per-exec       │                   │
  │  │ PROXY=  │   │ PROXY=   │   │  canary listener    │                   │
  │  │ proxy:  │   │ proxy:   │   │  (safe-field        │                   │
  │  │ 8788    │   │ 8788     │   │   callbacks on      │                   │
  │  │ NO_     │   │ NO_      │   │   SandboxExec       │                   │
  │  │ PROXY=  │   │ PROXY=   │   │   Capture; this     │                   │
  │  │ <infra> │   │ <infra>  │   │   lane ingests      │                   │
  │  │         │   │          │   │   into capture idx) │                   │
  │  └────┬────┘   └────┬─────┘   └──────────┬──────────┘                   │
  │       │             │                    │                              │
  │       └─────────────┼────────────────────┘                              │
  │                     │  (canary callbacks: per-exec in-memory return,     │
  │                     │   ingested into capture index by activity consumer) │
  │                     ▼                                                   │
  │  ┌──────────────────────────────────────────────────────────────────┐   │
  │  │  Recording Proxy (mitmproxy + addon)                              │   │
  │  │  Internal port :8788 (NOT published to host)                      │   │
  │  │                                                                   │   │
  │  │  ┌──────────────┐   ┌──────────────┐   ┌────────────────────┐    │   │
  │  │  │ Capture store │   │ SQLite index │   │ Addon logic:       │    │   │
  │  │  │ blobs/<sha>   │   │ url_template │   │ hash, normalize,   │    │   │
  │  │  │ (disposable)  │   │ dedup, query │   │ index, store       │    │   │
  │  │  │              │   │ canary_callback│  │                    │    │   │
  │  │  │              │   │ hunt_task_id  │   │                    │    │   │
  │  │  └──────────────┘   └──────────────┘   └────────────────────┘    │   │
  │  └──────────────────────────────────────────────────────────────────┘   │
  │                                                                          │
  │  ┌──────────────────────────────────────────────────────────────────┐   │
  │  │  Evidence Store (content-addressed by redacted bytes)             │   │
  │  │  blobs/<2hex>/<sha256>.bin                                        │   │
  │  │  ┌──────────────┐   ┌──────────────┐   ┌────────────────────┐    │   │
  │  │  │ Redact then  │   │ Verify-on-   │   │ Writer lock during │    │   │
  │  │  │ staged write │   │ read         │   │ snapshot           │    │   │
  │  │  │ (digest over │   │              │   │ (LOCK_EX;          │    │   │
  │  │  │  scrubbed    │   │              │   │ reclamation uses   │    │   │
  │  │  │  bytes)      │   │              │   │ LOCK_NB skip)      │    │   │
  │  │  └──────────────┘   └──────────────┘   └────────────────────┘    │   │
  │  └──────────────────────────────────────────────────────────────────┘   │
  └──────────────────────────────────────────────────────────────────────────┘
```

## Key design decisions

### Agent HTTP scope and proxy funnel

"Agent HTTP" is HTTP requests initiated by quarry tools under proxy env injection.
The only real surface today is `http_request` (`src/quarry_tools/http_tool.py`),
which packages a validated `HttpRequestSpec` as a JSON dispatch payload routed to
the `quarry-control` Temporal activity worker — the worker container (with
`HTTP_PROXY` injected) sends the actual HTTP request. When the browser worker
lands (in-flight `spec/browser-worker-playwright`; "Status: planned"), its HTTP
SHALL also route through the proxy.

Infrastructure egress that SHALL NOT transit the proxy:
- **Model-provider egress**: LiteLLM calls to AI providers (OpenAI, Anthropic, etc.)
- **Temporal server communication**: activity heartbeats, workflow RPC, Temporal
  SDK internal HTTP
- **Login-flow / authentication egress**: OAuth token endpoints, credential
  vault access

The `NO_PROXY` environment variable is injected alongside `HTTP_PROXY`/`HTTPS_PROXY`
and SHALL list the hosts for these excluded destinations. Worker containers
respect `NO_PROXY` automatically via the standard `requests`/`urllib` proxy
bypass mechanism.

The network-policy refusal layer (`direct-http-circumvents-proxy-is-blocked`)
SHALL reference egress-policy-destination-sets (in-flight
`openspec/changes/egress-policy-destination-sets`). Note: that spec's authored
scope is sandbox-tier only (ContainerSandbox IP pinning, K8sJobSandbox
NetworkPolicy); its destination sets do not include a worker-container
agent-HTTP policy. This gap is deferred: agent-HTTP refusal at the worker
container is a reconciliation task (task 10) that records the gap and defers
enforcement until the egress spec covers agent-HTTP. The NO_PROXY list and the
destination-set exclusion list SHALL be reconciled so every host in NO_PROXY
has a corresponding destination-set entry where enforcement applies.

### Proxy vs recorder choice

See proposal.md design-decision table. mitmproxy wins on TLS interception maturity
(CONNECT tunnelling, certificate generation, HTTP/2) and Python addon API. A custom
recorder would need ~2000 LOC of security-critical network code.

The mitmproxy addon (~200 LOC) hooks `response()` to:
1. Serialize the full exchange (request line, headers, body; response line, headers, body)
2. Compute SHA-256 of the serialized bytes
3. Write blob to capture store as `<sha256>.bin`
4. Normalize URL to template (replace UUIDs, integers, base64 path segments with `{param}`)
5. INSERT or UPDATE the SQLite index row (host, url_template, method, status_code, sha256, timestamp, byte_count, canary_callback, hunt_task_id)
6. Pass through to the target unmodified

### URL template normalization

Path segments matching these patterns are replaced:
- UUID: `[0-9a-f]{8}-[0-9a-f]{4}-...` → `{uuid}`
- Integer id: `^\d+$` → `{id}`
- Base64 token: `^[A-Za-z0-9+/=]{20,}$` → `{token}`
- ISO date: `^\d{4}-\d{2}-\d{2}$` → `{date}`

Example: `/api/users/550e8400-e29b-41d4-a716-446655440000/orders?page=3`
→ template: `/api/users/{uuid}/orders?page={id}`

This is sufficient (ASSUMED) because parameter-matching is prefix-anchored on the path
and query; edge cases (pagination via cursor tokens, RESTful slugs) are caught by the
base64 token pattern or fall through as distinct templates — a false-negative in
template merging is safer (more templates) than a false-positive (collapsing distinct
resources).

### Evidence store layout

```
evidence_store_root/
  blobs/
    a1/
      a1b2c3d4e5f6...<sha256>.bin
    3f/
      3f8a9b...<sha256>.bin
  locks/           # advisory lock files (fcntl on Unix)
  _index.db        # SQLite tables: evidence_blobs (sha256, raw_capture_sha256,
                   #   byte_count, redacted, scrubber_hit_count, quarantine,
                   #   captured_at), finding_evidence_bindings (finding_id,
                   #   evidence_sha256, bound_at)
```

### Write path (staged)

1. Serialize exchange in text-safe format (headers as text, text bodies inline,
   binary bodies base64-encoded)
2. Pass serialized text through `quarry_models.redaction.scrub()` → redacted text
3. Write redacted text bytes to `blobs/<2hex>/.tmp.<random>`
4. Compute SHA-256 of the redacted temp file — THIS is the evidence filename digest
5. Compare byte count against expected length → mismatch → delete temp, record event, raise
6. `os.rename(temp, final)` — atomic on same filesystem
7. Record in evidence index DB with redacted digest, raw capture digest (for traceability),
   byte count, redacted flag, and scrubber hit count

### Read path (verify-on-read)

1. Open `blobs/<2hex>/<sha>.bin`
2. Stream through hashlib.sha256()
3. Compare hex digest against filename digest
4. Mismatch → raise `EvidenceVerificationError`, record event

### Writer-lock semantics

During evidence snapshot (on finding binding):
1. Acquire `fcntl.flock(LOCK_EX)` on `locks/snapshot.lock`
2. For each referenced exchange in capture index:
   a. Look up blob SHA-256 from capture index
   b. Copy blob from capture store to evidence store using staged write
   c. Record finding↔evidence binding
3. Release lock

Concurrent reclamation:
1. Try `fcntl.flock(LOCK_EX | LOCK_NB)` on `locks/snapshot.lock`
2. If held → skip this cycle (snapshot in progress), retry on next sweep
3. If acquired → proceed with deletion of unreferenced blobs

### Secret-redaction integration

Evidence exchange bytes MUST be serialized in a text-safe format before scrubbing
(see "Write path" above). After serialization, the text passes through
`quarry_models.redaction.Scrubber.scrub()`:
```python
from quarry_models.redaction import Scrubber

scrubber = Scrubber()                              # per-run instance
scrubber.register_secret(runtime_api_key)          # optional: registered secrets
serialized_text = serialize_exchange(exchange)     # text-safe: binary bodies base64
result = scrubber.scrub(serialized_text)            # ScrubResult(text=..., hits=N)
redacted_bytes = result.text.encode("utf-8")
# SHA-256 of redacted_bytes becomes the evidence filename
```
The per-run `Scrubber` instance (with `register_secret()` for runtime credentials) operates on text;
the exchange serialization format ensures all content (headers, text bodies, base64-encoded
binary bodies) is valid text. The scrubber handles auth headers
(`Authorization: Bearer` API keys matching provider patterns) and
registered runtime secrets. Binary body content (images, binary responses) is
base64-preserved and NOT redacted by design — its bytes are opaque payloads.

The evidence index records `redacted=True`, `scrubber_hit_count=N`, and the
`raw_capture_sha256` (the pre-redaction digest from the capture index, for
traceability). Evidence blobs are content-addressed by their REDACTED digest;
the raw digest is metadata, not the filename.

Redaction is applied ONLY to evidence storage, NOT to the disposable capture —
capture preserves raw bytes for debugging while evidence is the scrubbed
distribution copy.

### Quarantine integration

Evidence artifacts inherit the quarantine policy from proof-artifact-quarantine
(B17 t_57f46027):
- `quarantine: True` at creation
- `executable_bit: False` enforced at storage
- Size limit per ArtifactKind enforced before staged write
- Local-only by default (refused remote write without explicit opt-in)

### Canary-callback ingestion (B10 canary-callback-listener @ 2a9fc6c)

The B10 per-exec canary listener (started/stopped inside `sandbox-exec`) returns
safe-field callbacks — `method`, `path` (length-capped ≤2048), `source_ip`,
`timestamp`; no headers or body — on `SandboxExecCapture.canary_callbacks` as
an in-memory return value. This lane owns the write-side mapping: the worker-side
activity consumer reads those callbacks from the `SandboxExecCapture` return and
writes each callback as a row in the capture index:

1. `sandbox-exec` activity completes, returning `SandboxExecCapture` with
   `canary_callbacks` populated
2. Worker-side activity consumer reads `canary_callbacks` from the capture
3. For each callback, INSERTs a row in the capture index with
   `canary_callback=True` and the originating `hunt_task_id`
4. Callbacks appear in capture-index queries alongside proxied traffic

This makes canary-callback exchanges queryable and correlated with hunt tasks
without requiring target-side proxy injection or listener-side SQLite access.
The correlation column (`hunt_task_id`) links each callback to the hunt that
placed the canary.

The canary listener lifecycle and topology (Tier 1: loopback thread on
`127.0.0.1` in the worker process; Tier 2: sidecar on the target's reachable
network, host-reachable address) are owned by B10. This change does NOT re-pin
the listener's network placement or lifecycle.

### Source attribution

Mechanisms derived from ARTEX v0.3.15 (github.com/Autumn-27/artex, AGPL-3.0):
- Recording MITM proxy: traffic/traffic.go (go-mitmproxy + SQLite index)
- Evidence store: evidence/store.go (staged write, hash verify)
- Writer-lock: traffic/evidence.go (ReadEvidence lock)
- URL template normalization: traffic/traffic.go exchanges schema (`url_template` column) + db/nkey.go `TemplatePath` substitution

Re-derived cleanly for Python/Temporal — no code imported, no license
contamination. Attribution recorded in THIRD_PARTY_NOTICES.md.

Additional design input from Pentest-Swarm-AI (Apache-2.0) oracle probes and
canary infrastructure (internal/swarm/verify/oracle/oob.go, interactsh session)
— mechanism concept only, re-derived for our Python stack.