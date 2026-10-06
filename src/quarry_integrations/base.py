"""Finding-sink interface, delivery context, and idempotency helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import uuid4

# Back-compat re-export (cruft-purge §4.7): FindingSink lives in the
# dependency-free leaf quarry.plugin_types; pre-hoist import paths keep working.
from quarry.plugin_types import FindingSink as FindingSink
from quarry.schemas import (
    ArtifactRef,
    FinalFinding,
    IntegrationRun,
    IntegrationStatus,
    utc_now,
)
from quarry_artifacts.local import LocalArtifactStore


def build_idempotency_key(scan_id: str, sink_name: str, fingerprint: str) -> str:
    """Scan-scoped key so a finding is delivered once per (scan, sink)."""
    return f"{scan_id}:{sink_name}:{fingerprint}"


def _empty_str_set() -> set[str]:
    return set()


@dataclass
class DeliveryContext:
    scan_id: str
    workspace_id: str
    dry_run: bool
    artifact_store: LocalArtifactStore | None = None
    already_delivered: set[str] = field(default_factory=_empty_str_set)


def make_run(
    *,
    sink_name: str,
    finding: FinalFinding,
    key: str,
    status: IntegrationStatus,
    dry_run: bool,
    output_ref: ArtifactRef | None = None,
    external_ref_id: str | None = None,
    error: str | None = None,
) -> IntegrationRun:
    """Construct an IntegrationRun for a (sink, finding) delivery."""
    now = utc_now()
    return IntegrationRun(
        id=str(uuid4()),
        scan_id=finding.scan_id,
        integration_config_id=f"local-{sink_name}",
        integration_event_id=finding.id,
        idempotency_key=key,
        status=status,
        dry_run=dry_run,
        sink=sink_name,
        finding_fingerprint=finding.fingerprint,
        external_ref_id=external_ref_id,
        output_ref=output_ref,
        error=error,
        created_at=now,
        completed_at=now,
    )


def already_delivered_run(sink_name: str, finding: FinalFinding, key: str) -> IntegrationRun:
    """A SKIPPED run for a finding already delivered in this scan (no side effects)."""
    return make_run(
        sink_name=sink_name,
        finding=finding,
        key=key,
        status=IntegrationStatus.SKIPPED,
        dry_run=True,
    )
