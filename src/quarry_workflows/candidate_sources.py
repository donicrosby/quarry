"""Deterministic-sweep candidate-source converters for the scan workflow.

Extracted from ``run_scan.py`` (cruft-purge §5.1) — pure move, no logic
edits. These converters turn activity payloads from the deterministic
secret/SSRF/tempfile-race/terminal-escape sweeps into ``CandidateFinding``
objects for the full-scan HUNT stage.

These functions run directly inside sandboxed Temporal workflow code (see
``RunScanWorkflow._run`` in ``run_scan.py``), so they must be pure and
deterministic: payloads cross the workflow/activity boundary as plain dicts
and no activity-side classes are imported (Temporal sandbox determinism).
Callers pass in ``created_at`` from ``workflow.now()`` at the call site.

Back-compat: ``run_scan.py`` re-exports the public converters from this
module so existing importers (tests, integration callers) keep working
unmigrated.
"""

from datetime import datetime
from typing import cast

from quarry.fingerprints import compute_fingerprint as _compute_fingerprint
from quarry.fingerprints import compute_root_cause_key as _compute_root_cause_key
from quarry.schemas import (
    CandidateFinding,
    Confidence,
    EvidencePathElement,
    SourceRef,
    VulnerabilityClass,
    model_omitted_severity_rationale,
)


def secret_candidates_from_activity_payload(
    payload: object,
    *,
    scan_id: str,
    created_at: datetime,
) -> list[CandidateFinding]:
    """Convert a ``scan-repo-for-secrets`` activity payload (raw dict list) to
    key_name-carrying CandidateFindings for the full-scan HUNT stage.

    The payload crosses the workflow/activity boundary as plain dicts; no
    activity-side classes are imported here (Temporal sandbox determinism).
    *created_at* comes from ``workflow.now()`` at the call site.
    """
    if not isinstance(payload, list):
        msg = f"Unexpected secret match payload: {type(payload).__name__}"
        raise TypeError(msg)
    candidates: list[CandidateFinding] = []
    for item in cast("list[object]", payload):
        record: dict[str, object] | None = (
            cast("dict[str, object]", item) if isinstance(item, dict) else None
        )
        if record is None:
            continue
        key_name = str(record.get("key_name", ""))
        file_path = str(record.get("file_path", ""))
        line_number = int(str(record.get("line_number", 0) or 0))
        if not key_name or not file_path or line_number <= 0:
            continue
        candidates.append(
            _secret_candidate_from_match_record(
                key_name=key_name,
                file_path=file_path,
                line_number=line_number,
                scan_id=scan_id,
                created_at=created_at,
            )
        )
    return candidates


def _secret_candidate_from_match_record(
    *,
    key_name: str,
    file_path: str,
    line_number: int,
    scan_id: str,
    created_at: datetime,
) -> CandidateFinding:
    """Workflow-deterministic mirror of the plugin's candidate builder.

    Same fingerprint inputs as ``quarry_plugins.vuln_classes.secrets`` so a
    secret found by both the deterministic sweep and an agent gets the same
    candidate id (dedup then collapses them).
    """
    fingerprint = _compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path=file_path,
        start_line=line_number,
        key_name=key_name,
        evidence_kind="hardcoded_assignment",
    )
    root_cause_key = _compute_root_cause_key(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path=file_path,
        sink=key_name,
    )
    return CandidateFinding(
        id=fingerprint[:32],
        scan_id=scan_id,
        workspace_id="local",
        vuln_class=VulnerabilityClass.SECRETS,
        title=f"Hardcoded secret: {key_name}",
        hypothesis=f"Variable '{key_name}' in {file_path}:{line_number} "
        f"contains a hardcoded value that may be a secret.",
        root_cause_key=root_cause_key,
        affected_component=file_path,
        source_refs=[
            SourceRef(
                file_path=file_path,
                start_line=line_number,
                end_line=line_number,
                symbol=key_name,
            )
        ],
        evidence_path=[],
        confidence=Confidence.MEDIUM,
        severity_rationale=model_omitted_severity_rationale(),
        created_by="secrets-scanner",
        created_at=created_at,
        metadata={
            "key_name": key_name,
            "evidence_kind": "hardcoded_assignment",
        },
    )


def ssrf_candidates_from_activity_payload(
    payload: object,
    *,
    scan_id: str,
    created_at: datetime,
) -> list[CandidateFinding]:
    """Convert a ``scan-repo-for-ssrf-sinks`` activity payload to SSRF candidates.

    Deterministic-sweep parity with ``secret_candidates_from_activity_payload``:
    the SSRF hunt task is a single model roll and missed the fixture app's
    obvious urlopen sink in run 8 (24af6f8d) while every model-side safety net
    silently failed. Sweep candidates are ordinary candidates — exploitability
    adjudication stays with the agentic ensemble + per-class dynamic
    evaluator; ``metadata.source == "ssrf-sweep"`` keeps provenance visible.

    The payload crosses the workflow/activity boundary as plain dicts; no
    activity-side classes are imported here (Temporal sandbox determinism).
    *created_at* comes from ``workflow.now()`` at the call site.
    """
    if not isinstance(payload, list):
        msg = f"Unexpected SSRF sink payload: {type(payload).__name__}"
        raise TypeError(msg)
    candidates: list[CandidateFinding] = []
    for item in cast("list[object]", payload):
        record: dict[str, object] | None = (
            cast("dict[str, object]", item) if isinstance(item, dict) else None
        )
        if record is None:
            continue
        sink_name = str(record.get("sink_name", ""))
        file_path = str(record.get("file_path", ""))
        line_number = int(str(record.get("line_number", 0) or 0))
        url_source = str(record.get("url_source", ""))
        if not sink_name or not file_path or line_number <= 0:
            continue
        fingerprint = _compute_fingerprint(
            vuln_class=VulnerabilityClass.SSRF,
            file_path=file_path,
            start_line=line_number,
            key_name=sink_name,
            evidence_kind="outbound_request_sink",
        )
        root_cause_key = _compute_root_cause_key(
            vuln_class=VulnerabilityClass.SSRF,
            file_path=file_path,
            sink=sink_name,
        )
        candidates.append(
            CandidateFinding(
                id=fingerprint[:32],
                scan_id=scan_id,
                workspace_id="local",
                vuln_class=VulnerabilityClass.SSRF,
                title=f"Outbound request sink: {sink_name}({url_source or '...'})",
                hypothesis=f"'{sink_name}' in {file_path}:{line_number} issues an "
                f"outbound server-side request whose destination is the variable "
                f"'{url_source}' — if that value is influenced by untrusted input "
                f"without scheme/host validation, this is exploitable SSRF.",
                root_cause_key=root_cause_key,
                affected_component=file_path,
                source_refs=[
                    SourceRef(
                        file_path=file_path,
                        start_line=line_number,
                        end_line=line_number,
                        symbol=sink_name,
                    )
                ],
                evidence_path=[EvidencePathElement(path=file_path, line=line_number)],
                confidence=Confidence.MEDIUM,
                severity_rationale=model_omitted_severity_rationale(),
                created_by="ssrf-sweep",
                created_at=created_at,
                metadata={
                    "source": "ssrf-sweep",
                    "evidence_kind": "outbound_request_sink",
                    "sink_name": sink_name,
                    "url_source": url_source,
                },
            )
        )
    return candidates


def fuzz_candidates_from_activity_payload(
    payload: object,
    *,
    scan_id: str,
    created_at: datetime,
    vuln_class: VulnerabilityClass,
) -> list[CandidateFinding]:
    """Convert a ``fuzz`` activity payload to one candidate per unique crash.

    Deterministic-sweep parity with the secrets/SSRF converters: the payload
    crosses the workflow/activity boundary as a plain dict (a ``FuzzResult``
    serialised by Temporal), and no activity-side classes are imported here
    (Temporal sandbox determinism).  A non-``ran`` pass (skipped/refused/failed)
    yields nothing, so the caller records the skip and proceeds.

    ``vuln_class`` is the scan's single focused class — the fuzz dispatch gate
    guarantees exactly one (requirement ``Fuzz dispatch gates on single-class
    focus``).  *created_at* comes from ``workflow.now()`` at the call site.
    """
    data = _as_mapping(payload)
    if data is None or data.get("status") != "ran":
        return []
    raw_crashes = data.get("crashes")
    if not isinstance(raw_crashes, list):
        return []
    candidates: list[CandidateFinding] = []
    for item in cast("list[object]", raw_crashes):
        record = _as_mapping(item)
        if record is None:
            continue
        candidate = _fuzz_candidate_from_crash_record(
            record, scan_id=scan_id, created_at=created_at, vuln_class=vuln_class
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _as_mapping(value: object) -> dict[str, object] | None:
    """Return *value* as a ``dict`` when it is one (or model-dumps like one)."""
    if isinstance(value, dict):
        return cast("dict[str, object]", value)
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        dumped = dump()
        if isinstance(dumped, dict):
            return cast("dict[str, object]", dumped)
    return None


def _fuzz_candidate_from_crash_record(
    record: dict[str, object],
    *,
    scan_id: str,
    created_at: datetime,
    vuln_class: VulnerabilityClass,
) -> CandidateFinding | None:
    """Workflow-deterministic builder for one fuzz crash candidate."""
    crash_hash = str(record.get("crash_hash", "") or "")
    if not crash_hash:
        return None
    trigger_input = str(record.get("trigger_input", "") or "")
    signal = str(record.get("signal", "") or "")
    sanitizer = str(record.get("sanitizer", "") or "")
    kind = str(record.get("kind", "") or "")
    seed = int(str(record.get("seed", 0) or 0))
    run_index = int(str(record.get("run_index", 0) or 0))
    stderr_length = int(str(record.get("stderr_length", 0) or 0))
    stderr_artifact_ref = str(record.get("stderr_artifact_ref", "") or "")
    component = str(record.get("component", "") or "") or "fuzz"
    crash_kind = sanitizer or signal or kind or "unknown"
    fingerprint = _compute_fingerprint(
        vuln_class=vuln_class,
        file_path=component,
        start_line=0,
        key_name=crash_hash[:16],
        evidence_kind="fuzz_crash",
    )
    root_cause_key = _compute_root_cause_key(
        vuln_class=vuln_class,
        file_path=component,
        sink=crash_hash[:16],
    )
    return CandidateFinding(
        id=fingerprint[:32],
        scan_id=scan_id,
        workspace_id="local",
        vuln_class=vuln_class,
        title=f"Fuzz crash ({crash_kind}) in {component}",
        hypothesis=f"Fuzzing the entry point {component} produced a {crash_kind} "
        f"crash (hash {crash_hash[:16]}); the crashing input was replayed in the "
        f"sandbox.",
        root_cause_key=root_cause_key,
        affected_component=component,
        source_refs=[],
        evidence_path=[],
        confidence=Confidence.MEDIUM,
        created_by="fuzz",
        created_at=created_at,
        trigger_input=trigger_input,
        metadata={
            "source": "fuzz",
            "fingerprint": fingerprint,
            "crash_hash": crash_hash,
            "kind": kind,
            "signal": signal,
            "sanitizer": sanitizer,
            "seed": seed,
            "run_index": run_index,
            "stderr_length": stderr_length,
            "stderr_artifact_ref": stderr_artifact_ref,
        },
    )


def tempfile_race_candidates_from_activity_payload(
    payload: object,
    *,
    scan_id: str,
    created_at: datetime,
) -> list[CandidateFinding]:
    """Convert a ``scan-repo-for-tempfile-races`` activity payload to candidates.

    Deterministic-sweep parity with the secrets/SSRF sweeps: predictable temp
    paths and deprecated name-then-open tempfile APIs open a TOCTOU window, so
    detection must not ride on one hunt roll.  ``metadata.source ==
    "tempfile-race-sweep"`` keeps sweep provenance visible to the coverage
    ledger and accumulator.

    The payload crosses the workflow/activity boundary as plain dicts; no
    activity-side classes are imported here (Temporal sandbox determinism).
    *created_at* comes from ``workflow.now()`` at the call site.
    """
    if not isinstance(payload, list):
        msg = f"Unexpected tempfile-race match payload: {type(payload).__name__}"
        raise TypeError(msg)
    candidates: list[CandidateFinding] = []
    for item in cast("list[object]", payload):
        record: dict[str, object] | None = (
            cast("dict[str, object]", item) if isinstance(item, dict) else None
        )
        if record is None:
            continue
        sink_name = str(record.get("sink_name", ""))
        file_path = str(record.get("file_path", ""))
        line_number = int(str(record.get("line_number", 0) or 0))
        temp_path = str(record.get("temp_path", ""))
        evidence_kind = str(record.get("evidence_kind", "predictable_temp_path"))
        if not sink_name or not file_path or line_number <= 0:
            continue
        fingerprint = _compute_fingerprint(
            vuln_class=VulnerabilityClass.TEMPFILE_RACE,
            file_path=file_path,
            start_line=line_number,
            key_name=sink_name,
            evidence_kind=evidence_kind,
        )
        root_cause_key = _compute_root_cause_key(
            vuln_class=VulnerabilityClass.TEMPFILE_RACE,
            file_path=file_path,
            sink=sink_name,
        )
        target = f" at {temp_path}" if temp_path else ""
        candidates.append(
            CandidateFinding(
                id=fingerprint[:32],
                scan_id=scan_id,
                workspace_id="local",
                vuln_class=VulnerabilityClass.TEMPFILE_RACE,
                title=f"Unsafe temporary file: {sink_name}",
                hypothesis=f"'{sink_name}' in {file_path}:{line_number} creates or "
                f"uses a temporary file with a predictable name or deprecated "
                f"name-then-open API{target}; an attacker who pre-plants that path "
                f"wins the TOCTOU window.",
                root_cause_key=root_cause_key,
                affected_component=file_path,
                source_refs=[
                    SourceRef(
                        file_path=file_path,
                        start_line=line_number,
                        end_line=line_number,
                        symbol=sink_name,
                    )
                ],
                evidence_path=[EvidencePathElement(path=file_path, line=line_number)],
                confidence=Confidence.MEDIUM,
                severity_rationale=model_omitted_severity_rationale(),
                created_by="tempfile-race-sweep",
                created_at=created_at,
                metadata={
                    "source": "tempfile-race-sweep",
                    "evidence_kind": evidence_kind,
                    "sink_name": sink_name,
                    "temp_path": temp_path,
                },
            )
        )
    return candidates


def terminal_escape_candidates_from_activity_payload(
    payload: object,
    *,
    scan_id: str,
    created_at: datetime,
) -> list[CandidateFinding]:
    """Convert a ``scan-repo-for-terminal-escapes`` activity payload to candidates.

    Deterministic-sweep parity with the secrets/SSRF sweeps: attacker-controlled
    input echoed to a terminal without ANSI sanitization is presence-shaped, so
    detection must not ride on one hunt roll.  ``metadata.source ==
    "terminal-escape-sweep"`` keeps sweep provenance visible to the coverage
    ledger and accumulator.

    The payload crosses the workflow/activity boundary as plain dicts; no
    activity-side classes are imported here (Temporal sandbox determinism).
    *created_at* comes from ``workflow.now()`` at the call site.
    """
    if not isinstance(payload, list):
        msg = f"Unexpected terminal-escape match payload: {type(payload).__name__}"
        raise TypeError(msg)
    candidates: list[CandidateFinding] = []
    for item in cast("list[object]", payload):
        record: dict[str, object] | None = (
            cast("dict[str, object]", item) if isinstance(item, dict) else None
        )
        if record is None:
            continue
        sink_name = str(record.get("sink_name", ""))
        file_path = str(record.get("file_path", ""))
        line_number = int(str(record.get("line_number", 0) or 0))
        input_source = str(record.get("input_source", ""))
        evidence_kind = str(record.get("evidence_kind", "unsanitized_terminal_output"))
        if not sink_name or not file_path or line_number <= 0:
            continue
        fingerprint = _compute_fingerprint(
            vuln_class=VulnerabilityClass.TERMINAL_ESCAPE,
            file_path=file_path,
            start_line=line_number,
            key_name=sink_name,
            evidence_kind=evidence_kind,
        )
        root_cause_key = _compute_root_cause_key(
            vuln_class=VulnerabilityClass.TERMINAL_ESCAPE,
            file_path=file_path,
            sink=sink_name,
        )
        candidates.append(
            CandidateFinding(
                id=fingerprint[:32],
                scan_id=scan_id,
                workspace_id="local",
                vuln_class=VulnerabilityClass.TERMINAL_ESCAPE,
                title=f"Unsanitized terminal output: {sink_name}",
                hypothesis=f"'{sink_name}' in {file_path}:{line_number} writes the "
                f"user-controlled value '{input_source}' to a terminal without "
                f"stripping ANSI/control sequences, letting injected escapes "
                f"manipulate the operator display.",
                root_cause_key=root_cause_key,
                affected_component=file_path,
                source_refs=[
                    SourceRef(
                        file_path=file_path,
                        start_line=line_number,
                        end_line=line_number,
                        symbol=sink_name,
                    )
                ],
                evidence_path=[EvidencePathElement(path=file_path, line=line_number)],
                confidence=Confidence.MEDIUM,
                severity_rationale=model_omitted_severity_rationale(),
                created_by="terminal-escape-sweep",
                created_at=created_at,
                metadata={
                    "source": "terminal-escape-sweep",
                    "evidence_kind": evidence_kind,
                    "sink_name": sink_name,
                    "input_source": input_source,
                },
            )
        )
    return candidates
