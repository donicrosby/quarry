"""Deterministic-sweep candidate-source converters for the scan workflow.

Extracted from ``run_scan.py`` (cruft-purge §5.1) — pure move, no logic
edits. These converters turn activity payloads from the deterministic
secret/SSRF sweeps into ``CandidateFinding`` objects for the full-scan HUNT
stage.

These functions run directly inside sandboxed Temporal workflow code (see
``RunScanWorkflow._run`` in ``run_scan.py``), so they must be pure and
deterministic: payloads cross the workflow/activity boundary as plain dicts
and no activity-side classes are imported (Temporal sandbox determinism).
Callers pass in ``created_at`` from ``workflow.now()`` at the call site.

Back-compat: ``run_scan.py`` re-exports both public converters from this
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
