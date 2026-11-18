# Tasks: proof-artifact-quarantine

- [ ] 1. **Quarantine field on ProofArtifact model**
  SHALL add a `quarantine: bool = True` field to `ProofArtifact` in
  `src/quarry/schemas.py`; default `True` (fail-closed). No migration needed —
  new field with a safe default.

- [ ] 2. **Hash recording on proof artifact acceptance**
  SHALL compute `sha256` of the artifact bytes at storage time and populate
  `ArtifactRef.sha256`. Targets the proof artifact construction site in
  `src/quarry_workflows/run_scan.py` (currently sha256="" at :3807; reports
  already hash at :4048 as a reference implementation).

- [ ] 3. **Executable-bit clearing for binary artifacts**
  SHALL clear the execute permission bits (owner/group/other) on stored binary
  proof artifacts. Targets `src/quarry_artifacts/local.py` — the
  `LocalArtifactStore.put_bytes` method, gated on `ArtifactKind` being a
  proof-related kind (TOOL_STDOUT, TOOL_STDERR, HTTP_RESPONSE).

- [ ] 4. **Per-kind size limit enforcement**
  SHALL add a configurable `max_size_bytes` per `ArtifactKind` via
  `QuarrySettings`, with safe defaults (e.g., 1 MB for stdout/stderr, 100 MB
  for HTTP response bodies, 5 MB for code snippets). Enforce in
  `LocalArtifactStore.put_bytes` before any write; reject with a recorded event.

- [ ] 5. **Local-only quarantine guard**
  SHALL extend the existing `_LOCAL_BACKENDS` guard (currently scoped to prompt
  storage in `src/quarry_artifacts/store.py:176-184`) to proof artifacts: when
  the backend is non-local and no explicit remote quarantine destination is
  configured, refuse the write before any bytes egress. Add a
  `QUARRY_QUARANTINE_REMOTE_BACKEND` setting.

- [ ] 6. **Pluggable malware scan hook**
  SHALL define a `MalwareScanner` protocol in `src/quarry_artifacts/` with a
  single `scan(data: bytes) -> ScanResult` method. Wire a no-op default
  (`ScannerUnavailable`); when `QUARRY_MALWARE_SCANNER=clamav` is set, load
  the ClamAV integration (deferred to a follow-on change; this task creates
  the protocol and hook point only). SHALL record a scanner-skipped event
  when unconfigured and a detection event on a reported detection; the
  artifact remains quarantined on detection (no auto-release, no auto-delete).

- [ ] 7. **Validate and gate**
  SHALL run `npx openspec validate --strict` on the change, pass pre-commit,
  and verify every scenario's acceptance criterion against the test suite.
  Self-review: grep for `quarantine` across the whole tree and confirm the
  word appears in every touched file + spec.