"""Coverage ledger activity.

Records what a scan actually covered: which vulnerability classes were requested
and completed, how many agentic tasks were scanned versus emitted, and an
honest list of what was skipped and why. The ledger is stored as an artifact and
surfaced in the report so coverage gaps are never hidden.
"""

import json
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from temporalio import activity

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    CoverageGap,
    CoverageLedger,
    RedactionStatus,
    VulnerabilityClass,
    utc_now,
)
from quarry_activities.inputs import BuildCoverageLedgerInput, BuildCoverageLedgerOutput


def build_coverage_ledger(
    *,
    scan_id: str,
    workspace_id: str,
    requested_vuln_classes: list[VulnerabilityClass],
    completed_vuln_classes: list[VulnerabilityClass],
    agent_tasks_total: int,
    agent_tasks_scanned: int,
    skipped_items: list[CoverageGap],
    id: str | None = None,
    created_at: Any = None,
) -> CoverageLedger:
    """Build a coverage ledger from already-computed scan facts (no I/O).

    *id* and *created_at* may be supplied by workflow code (using
    ``workflow.uuid4()`` / ``workflow.now()``) to stay within the
    Temporal sandbox.  Both default to fresh values when called from
    activity or non-workflow code.
    """
    return CoverageLedger(
        id=id if id is not None else str(uuid4()),
        scan_id=scan_id,
        workspace_id=workspace_id,
        agent_tasks_total=agent_tasks_total,
        agent_tasks_scanned=agent_tasks_scanned,
        vuln_classes_requested=requested_vuln_classes,
        vuln_classes_completed=completed_vuln_classes,
        skipped_items=skipped_items,
        created_at=created_at if isinstance(created_at, datetime) else utc_now(),
    )


def write_coverage_artifact(ledger: CoverageLedger, artifact_root: Path | str) -> ArtifactRef:
    """Persist a coverage ledger as a JSON artifact and return its ArtifactRef."""
    ledger_path = Path(artifact_root) / ledger.scan_id / f"coverage-{ledger.id}.json"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    data = ledger.model_dump_json().encode("utf-8")
    ledger_path.write_bytes(data)
    return ArtifactRef(
        id=str(uuid4()),
        uri=f"file://{ledger_path}",
        kind=ArtifactKind.COVERAGE_LEDGER,
        content_type="application/json",
        sha256=sha256(data).hexdigest(),
        size_bytes=len(data),
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=utc_now(),
        metadata={"path": str(ledger_path)},
    )


@activity.defn(name="build-coverage-ledger")
def build_coverage_ledger_activity(
    input: BuildCoverageLedgerInput | dict[str, Any],
) -> BuildCoverageLedgerOutput:
    """Build the coverage ledger, persist it as an artifact, and return both."""
    if isinstance(input, dict):
        input = BuildCoverageLedgerInput(**input)
    ledger = build_coverage_ledger(
        scan_id=input.scan_id,
        workspace_id=input.workspace_id,
        requested_vuln_classes=[VulnerabilityClass(v) for v in input.requested_vuln_classes],
        completed_vuln_classes=[VulnerabilityClass(v) for v in input.completed_vuln_classes],
        agent_tasks_total=input.agent_tasks_total,
        agent_tasks_scanned=input.agent_tasks_scanned,
        skipped_items=_coverage_gaps_from_json(input.scan_id, input.skipped_json),
    )
    artifact_ref = write_coverage_artifact(ledger, input.artifact_root)
    return BuildCoverageLedgerOutput(
        ledger_json=ledger.model_dump_json(),
        artifact_ref_json=artifact_ref.model_dump_json(),
    )


def _coverage_gaps_from_json(scan_id: str, payload: str) -> list[CoverageGap]:
    raw = json.loads(payload)
    if not isinstance(raw, list):
        msg = "skipped_json must encode a JSON array"
        raise TypeError(msg)
    gaps: list[CoverageGap] = []
    for entry in cast(list[Any], raw):
        if not isinstance(entry, dict):
            msg = "each skipped entry must be a JSON object"
            raise TypeError(msg)
        values = cast(dict[str, Any], entry)
        vuln_class_value = values.get("vuln_class")
        gaps.append(
            CoverageGap(
                id=str(uuid4()),
                scan_id=scan_id,
                scope_unit_id=_optional_str(values.get("scope_unit_id")),
                vuln_class=(
                    VulnerabilityClass(vuln_class_value)
                    if isinstance(vuln_class_value, str)
                    else None
                ),
                reason=_required_str(values, "reason"),
                recommended_next_task=_optional_str(values.get("recommended_next_task")),
                severity_hint=_optional_str(values.get("severity_hint")),
            )
        )
    return gaps


def _required_str(values: dict[str, Any], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str):
        msg = f"{key} must be a string"
        raise TypeError(msg)
    return value


def _optional_str(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    msg = "value must be a string or None"
    raise TypeError(msg)
