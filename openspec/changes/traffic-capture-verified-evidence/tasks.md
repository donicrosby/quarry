# Tasks — traffic-capture-verified-evidence

## 1. Scaffold the mitmproxy addon module
- [ ] Create `src/quarry_traffic/` package with `__init__.py` and addon module
- [ ] Define addon class implementing mitmproxy's `response()` hook
- [ ] Serialize exchange to canonical byte format (request line, headers, body, response line, headers, body)
- [ ] Compute SHA-256 digest of serialized exchange
- [ ] Write blob to capture store directory as `<sha256>.bin`
- [ ] Implement URL template normalization (uuid, integer, base64-token, ISO-date patterns)
- [ ] Write unit tests: template normalization for each pattern class, blob write+hash, duplicate detection

## 2. Build the SQLite capture index
- [ ] Create `CaptureIndex` class with schema: host, sha256, url_template, method, status_code, timestamp, byte_count, canary_callback (bool), hunt_task_id (nullable text)
- [ ] INSERT or UPDATE on capture (upsert by sha256 to avoid duplicates)
- [ ] Implement query methods: by_url_template, by_status_code, by_time_range, by_host, by_canary_callback
- [ ] Write unit tests: index insert, upsert dedup, query by template, query by time range, canary-flagged rows are queryable

## 3. Wire proxy into the compose stack
- [ ] Add mitmproxy service to docker-compose.yml (internal network, port 8788 not published)
- [ ] Mount capture store volume and addon script
- [ ] Inject HTTP_PROXY/HTTPS_PROXY env vars into worker container definitions (quarry-control activity workers; browser workers when landed)
- [ ] Inject NO_PROXY env var listing model-provider hosts, Temporal server host, and auth hosts
- [ ] Verify traffic flows through proxy: integration test that sends known request, reads capture index, confirms blob exists
- [ ] Verify NO_PROXY exclusions: infrastructure requests bypass proxy, agent requests do not

## 4. Implement host-scoped export and reclamation
- [ ] Build `export_host(host: str) -> Path` method that produces a tar of host's exchanges + blobs
- [ ] Build `reclaim(max_bytes: int)` method that deletes unreferenced blobs and index rows
- [ ] Write unit tests: export produces portable archive, reclaim ignores referenced blobs (mock index)

## 5. Build the evidence store
- [ ] Create `src/quarry_traffic/evidence.py` with `EvidenceStore` class
- [ ] Implement text-safe exchange serialization (headers as text, text bodies inline, binary bodies base64-encoded)
- [ ] Implement staged write: serialize → scrub (see task 7) → write temp file → compute SHA-256 of redacted bytes → length check → atomic rename. The filename is the redacted digest
- [ ] Schema: `evidence_blobs` table (sha256, raw_capture_sha256, byte_count, redacted, scrubber_hit_count, quarantine, captured_at) and `finding_evidence_bindings` table (finding_id, evidence_sha256, bound_at)
- [ ] Implement verify-on-read (stream through hashlib, compare against filename digest)
- [ ] Implement writer-lock using fcntl.flock: snapshot holds LOCK_EX; reclamation tries LOCK_NB and skips if held
- [ ] Write unit tests: staged write happy path, digest mismatch rejection (over redacted bytes), length mismatch rejection, verify-on-read failure, lock held → reclamation skips, lock released → reclamation proceeds

## 6. Wire finding-binding snapshot
- [ ] Implement `snapshot_for_finding(exchange_refs: list[str], finding_id: str)` — reads capture blobs, applies scrub, writes to evidence store under writer lock using redacted digest as filename
- [ ] Record finding↔evidence binding in `finding_evidence_bindings` table
- [ ] Store `raw_capture_sha256` in evidence index for traceability
- [ ] Write unit tests: snapshot copies blobs (redacted), lock held during copy, evidence survives capture reclaim, raw_capture_sha256 recorded, finding↔evidence binding queryable

## 7. Integrate secret-redaction into evidence storage
- [ ] Implement text-safe exchange serialization for evidence path (binary body parts base64-encoded)
- [ ] Pass serialized exchange text through a per-run `Scrubber` instance (`Scrubber.scrub(text: str) -> ScrubResult`) before staged write; register runtime API keys via `Scrubber.register_secret()` where available
- [ ] Redaction runs BEFORE digest computation: the evidence filename is the SHA-256 of redacted bytes
- [ ] Record `redacted=True`, `scrubber_hit_count=N`, and `raw_capture_sha256` in evidence index
- [ ] Write unit tests: scrubber applies to evidence text (auth headers, API keys, registered secrets redacted), binary body base64 is preserved unredacted, redacted digest ≠ raw digest, capture blobs remain unredacted, raw_capture_sha256 traceable

## 8. Apply quarantine policy to evidence artifacts
- [ ] Set quarantine=True on evidence artifact creation (per proof-artifact-quarantine spec)
- [ ] Enforce no-exec on stored evidence
- [ ] Enforce size limits per ArtifactKind before staged write
- [ ] Refuse remote backend writes for quarantined evidence without explicit opt-in
- [ ] Write unit tests: quarantine flag set, exec bit cleared, oversize rejected, remote write refused

## 9. Ingest canary callbacks into capture index (B10 consumer)
- [ ] Implement worker-side activity consumer that reads `SandboxExecCapture.canary_callbacks` (safe-field entries: `method`, `path` length-capped ≤2048, `source_ip`, `timestamp`) from the `sandbox-exec` activity return
- [ ] For each callback, INSERT a row in the capture index with `canary_callback=True` and the originating `hunt_task_id`
- [ ] The capture-index write is owned by this lane's activity consumer — the B10 listener returns callbacks in-memory and does NOT write to SQLite
- [ ] Write integration test: simulate a `sandbox-exec` return with populated `canary_callbacks`, verify rows appear in capture index with `canary_callback=True` and correct `hunt_task_id`, queryable alongside proxied traffic

## 10. Reconcile proxy-bypass refusal with egress-policy-destination-sets
- [ ] **Note**: `egress-policy-destination-sets` @ 280689f has sandbox-tier enforcement only (ContainerSandbox IP pinning, K8sJobSandbox NetworkPolicy); its destination sets do not include a worker-container agent-HTTP policy. This task records the gap and defers enforcement until the egress spec is extended to cover agent-HTTP at the worker container.
- [ ] Ensure the NO_PROXY exclusion list (model-provider, Temporal, auth hosts) and the destination-set exclusion list are reconciled (every NO_PROXY host has a corresponding destination-set entry where enforcement applies)
- [ ] Add a non-blocking integration note in this change's design.md and defer the enforcement task until the egress spec covers agent-HTTP

## 11. Validate, commit, and push
- [ ] Run `npx -y @fission-ai/openspec validate traffic-capture-verified-evidence --strict` — must be clean (EXIT=0)
- [ ] Confirm spec deltas match shipped `src/` surface (`http_request` tool) and planned surfaces are marked "Status: planned"
- [ ] Commit all openspec files on branch `spec/traffic-capture-verified-evidence`
- [ ] Report tip SHA
- [ ] Try `gh auth setup-git` + push; park locally on failure

## Notes
- Browser-worker proxy integration (scenario `browser-worker-is-proxied`) is gated on `spec/browser-worker-playwright` landing; the scenario is marked "Status: planned" and no browser-worker implementation task is active in this change.
- The four regex pattern classes in design.md (UUID, integer, base64-token, ISO-date) are architectural specification. The non-goal "not defining exact parameter-pattern regexes" means the precise regex strings are an implementation detail, not specified here.
