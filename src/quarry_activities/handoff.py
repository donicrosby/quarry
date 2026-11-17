"""Versioned handoff artifact activities (versioned-handoff-artifacts).

ADR-026 rule 6: "Handoff over compaction for long tasks". This module owns the
three cold-start artifacts — ArchitectureDoc, CoverageLedger, HuntHandoff —
their canonical artifact-store keys, and the two activities that write and read
them:

* ``write-handoff-artifacts`` builds + persists all three at the end of a hunt
  round, each carrying ``scan_ordinal`` / ``artifact_version`` stamps so every
  version is uniquely identifiable and diffable across scans.
* ``load-handoff-artifacts`` reads them back so a fresh agent process can
  cold-start a resumed hunt from the artifacts alone (no Temporal workflow
  state, in-memory data, or conversation history).

Keys are deterministic and scoped to the scan id, so cold-start lookup needs
only the scan id and the artifact-store root.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from temporalio import activity

from quarry.schemas import (
    ArchitectureDoc,
    ArtifactKind,
    ArtifactRef,
    HuntHandoff,
    VulnerabilityClass,
    utc_now,
)
from quarry_activities.coverage import build_coverage_ledger
from quarry_activities.inputs import (
    LoadHandoffArtifactsInput,
    LoadHandoffArtifactsOutput,
    WriteHandoffArtifactsInput,
    WriteHandoffArtifactsOutput,
)
from quarry_artifacts.local import LocalArtifactStore


def architecture_doc_key(scan_id: str) -> str:
    """Canonical artifact-store key for a scan's ArchitectureDoc."""
    return f"{scan_id}/architecture-doc.json"


def coverage_ledger_key(scan_id: str) -> str:
    """Canonical artifact-store key for a scan's cold-start CoverageLedger."""
    return f"{scan_id}/coverage-ledger.json"


def hunt_handoff_key(scan_id: str) -> str:
    """Canonical artifact-store key for a scan's HuntHandoff."""
    return f"{scan_id}/hunt-handoff.json"


def _stamp_metadata(scan_ordinal: int, artifact_version: int) -> dict[str, str]:
    return {
        "scan_ordinal": str(scan_ordinal),
        "artifact_version": str(artifact_version),
    }


def _parse_created_at(value: str | None) -> datetime:
    """Parse the workflow-supplied ISO timestamp, defaulting to now()."""
    if value is None:
        return utc_now()
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=utc_now().tzinfo)
    return parsed


@activity.defn(name="write-handoff-artifacts")
def write_handoff_artifacts(
    input: WriteHandoffArtifactsInput | dict[str, Any],
) -> WriteHandoffArtifactsOutput:
    """Build + persist the three versioned handoff artifacts for one hunt round.

    The ArchitectureDoc is re-stamped with the current version and re-written
    (falling back to the copy recon already persisted when the workflow does not
    carry it in memory, e.g. on a resume). A fresh CoverageLedger is built from
    the supplied round facts. The HuntHandoff records what was covered, what was
    found, what remains, and the open hypotheses.
    """
    if isinstance(input, dict):
        input = WriteHandoffArtifactsInput(**input)

    store = LocalArtifactStore(input.artifact_root)
    created_at = _parse_created_at(input.created_at)
    stamps = _stamp_metadata(input.scan_ordinal, input.artifact_version)

    arch_ref: ArtifactRef | None = None
    arch_doc_json = input.architecture_doc_json
    if arch_doc_json is None:
        arch_doc_json = store.get_text(architecture_doc_key(input.scan_id))
    if arch_doc_json is not None:
        doc = ArchitectureDoc.model_validate_json(arch_doc_json).model_copy(
            update={
                "scan_ordinal": input.scan_ordinal,
                "artifact_version": input.artifact_version,
            }
        )
        arch_ref = store.put_json(
            architecture_doc_key(input.scan_id),
            doc,
            kind=ArtifactKind.ARCHITECTURE_DOC,
            metadata=stamps,
        )

    ledger = build_coverage_ledger(
        scan_id=input.scan_id,
        workspace_id=input.workspace_id,
        requested_vuln_classes=[VulnerabilityClass(v) for v in input.requested_vuln_classes],
        completed_vuln_classes=[VulnerabilityClass(v) for v in input.completed_vuln_classes],
        agent_tasks_total=input.agent_tasks_total,
        agent_tasks_scanned=input.agent_tasks_scanned,
        scan_ordinal=input.scan_ordinal,
        artifact_version=input.artifact_version,
        created_at=created_at,
    )
    ledger_ref = store.put_json(
        coverage_ledger_key(input.scan_id),
        ledger,
        kind=ArtifactKind.COVERAGE_LEDGER,
        metadata=stamps,
    )

    handoff = HuntHandoff(
        id=str(uuid4()),
        scan_id=input.scan_id,
        workspace_id=input.workspace_id,
        round_number=input.round_number,
        stage="HUNT",
        covered_scope_units=list(input.covered_scope_units),
        candidate_finding_ids=list(input.candidate_finding_ids),
        pending_task_ids=list(input.pending_task_ids),
        pending_task_count=len(input.pending_task_ids),
        open_hypotheses=list(input.open_hypotheses),
        scan_ordinal=input.scan_ordinal,
        artifact_version=input.artifact_version,
        created_at=created_at,
    )
    handoff_ref = store.put_json(
        hunt_handoff_key(input.scan_id),
        handoff,
        kind=ArtifactKind.HUNT_HANDOFF,
        metadata=stamps,
    )

    return WriteHandoffArtifactsOutput(
        hunt_handoff_json=handoff.model_dump_json(),
        hunt_handoff_ref_json=handoff_ref.model_dump_json(),
        architecture_doc_ref_json=arch_ref.model_dump_json() if arch_ref is not None else None,
        coverage_ledger_ref_json=ledger_ref.model_dump_json(),
    )


@activity.defn(name="load-handoff-artifacts")
def load_handoff_artifacts(
    input: LoadHandoffArtifactsInput | dict[str, Any],
) -> LoadHandoffArtifactsOutput:
    """Read the three cold-start artifacts for a scan back from the store.

    Returns ``found=False`` when no HuntHandoff exists (a fresh start); the
    architecture-doc / coverage-ledger payloads are returned independently when
    present.
    """
    if isinstance(input, dict):
        input = LoadHandoffArtifactsInput(**input)

    store = LocalArtifactStore(input.artifact_root)
    handoff_text = store.get_text(hunt_handoff_key(input.scan_id))
    if handoff_text is None:
        return LoadHandoffArtifactsOutput(found=False)
    return LoadHandoffArtifactsOutput(
        found=True,
        hunt_handoff_json=handoff_text,
        architecture_doc_json=store.get_text(architecture_doc_key(input.scan_id)),
        coverage_ledger_json=store.get_text(coverage_ledger_key(input.scan_id)),
    )
