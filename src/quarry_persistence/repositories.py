import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import ForeignKey, Integer, String, Text, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapped, Session, mapped_column

from quarry.schemas import (
    ArchitectureDoc,
    ArtifactRef,
    AttackSurfaceItem,
    CandidateFinding,
    FinalFinding,
    IntegrationRun,
    ModelInvocation,
    Report,
    Scan,
    ScanManifest,
    ScanStatus,
    Target,
    ToolInvocation,
    WorkflowEvent,
)
from quarry_persistence.db import Base, create_sqlite_engine, session_scope


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String, nullable=False)
    target_id: Mapped[str] = mapped_column(String, nullable=False)
    target_repo_path: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    profile_id: Mapped[str] = mapped_column(String, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    report_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[str | None] = mapped_column(String, nullable=True)
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    scan_json: Mapped[str] = mapped_column(Text, nullable=False)
    target_json: Mapped[str] = mapped_column(Text, nullable=False)


class WorkflowEventRecord(Base):
    __tablename__ = "workflow_events"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String, nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)


class ArtifactRefRecord(Base):
    __tablename__ = "artifact_refs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    uri: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_json: Mapped[str] = mapped_column(Text, nullable=False)


class CandidateFindingRecord(Base):
    __tablename__ = "candidate_findings"

    # Finding ids are deterministic fingerprints (stable across scans by design),
    # so the primary key is scoped per scan to allow re-scanning the same repo.
    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id"), primary_key=True, nullable=False
    )
    workspace_id: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    vuln_class: Mapped[str] = mapped_column(String, nullable=False)
    finding_json: Mapped[str] = mapped_column(Text, nullable=False)


class AttackSurfaceItemRecord(Base):
    __tablename__ = "attack_surface_items"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    route: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(String, nullable=False)
    handler_file: Mapped[str] = mapped_column(Text, nullable=False)
    item_json: Mapped[str] = mapped_column(Text, nullable=False)


class ReportRecord(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String, nullable=False)
    report_path: Mapped[str] = mapped_column(Text, nullable=False)
    report_json: Mapped[str] = mapped_column(Text, nullable=False)


class FinalFindingRecord(Base):
    __tablename__ = "final_findings"

    # Fingerprint-derived ids are stable across scans, so scope the key per scan.
    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String, ForeignKey("scans.id"), primary_key=True, nullable=False
    )
    workspace_id: Mapped[str] = mapped_column(String, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    vuln_class: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    finding_json: Mapped[str] = mapped_column(Text, nullable=False)


class IntegrationRunRecord(Base):
    __tablename__ = "integration_runs"

    # idempotency_key is scan-scoped (scan_id:sink:fingerprint) and unique, so it
    # is the primary key: re-delivering the same finding upserts the same row.
    idempotency_key: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    sink: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    run_json: Mapped[str] = mapped_column(Text, nullable=False)


class ScanManifestRecord(Base):
    __tablename__ = "scan_manifests"

    # One manifest per scan; scan_id is the key so resume re-writes are idempotent.
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), primary_key=True)
    manifest_json: Mapped[str] = mapped_column(Text, nullable=False)


class ArchitectureDocRecord(Base):
    __tablename__ = "architecture_docs"

    # One ArchitectureDoc per scan; merge-on-save is idempotent.
    # Note: SQLite does not enforce FKs by default (no PRAGMA foreign_keys=ON),
    # so ReconWorkflow can persist docs for scan_ids that have no row in 'scans'
    # (e.g. when run standalone without RunScanWorkflow). This is intentional.
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), primary_key=True)
    doc_json: Mapped[str] = mapped_column(Text, nullable=False)


class ToolInvocationRecord(Base):
    __tablename__ = "tool_invocations"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    tool_name: Mapped[str] = mapped_column(String, nullable=False)
    invocation_json: Mapped[str] = mapped_column(Text, nullable=False)


class ModelInvocationRecord(Base):
    __tablename__ = "model_invocations"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False)
    invocation_json: Mapped[str] = mapped_column(Text, nullable=False)


@dataclass(frozen=True)
class ScanSummary:
    scan_id: str
    repo_path: str
    status: str
    profile_id: str
    event_count: int
    report_path: str | None
    created_at: str
    completed_at: str | None
    error: str | None = None


class QuarryRepository:
    def __init__(self, db_path: Path | str | None = None) -> None:
        self.engine = create_sqlite_engine(db_path)
        Base.metadata.create_all(self.engine)

    @classmethod
    def from_engine(cls, engine: Engine) -> "QuarryRepository":
        repository = cls.__new__(cls)
        repository.engine = engine
        Base.metadata.create_all(engine)
        return repository

    def create_scan(self, scan: Scan, target: Target) -> None:
        with session_scope(self.engine) as session:
            session.add(
                ScanRecord(
                    id=scan.id,
                    workspace_id=scan.workspace_id,
                    target_id=scan.target_id,
                    target_repo_path=target.repo_path,
                    status=scan.status.value,
                    profile_id=scan.profile.id,
                    event_count=0,
                    report_path=None,
                    created_at=_encode_datetime(scan.created_at),
                    started_at=_encode_optional_datetime(scan.started_at),
                    completed_at=_encode_optional_datetime(scan.completed_at),
                    scan_json=scan.model_dump_json(),
                    target_json=target.model_dump_json(),
                )
            )

    def update_scan_status(
        self,
        scan_id: str,
        status: ScanStatus,
        *,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        report_path: Path | str | None = None,
        error: str | None = None,
    ) -> None:
        with session_scope(self.engine) as session:
            record = _get_scan_record(session, scan_id)
            scan = Scan.model_validate_json(record.scan_json)
            record.status = status.value
            record.started_at = _encode_optional_datetime(started_at) or record.started_at
            record.completed_at = _encode_optional_datetime(completed_at) or record.completed_at
            if report_path is not None:
                record.report_path = str(report_path)
            if error is not None:
                record.error = error
            record.scan_json = scan.model_copy(
                update={
                    "status": status,
                    "started_at": started_at or scan.started_at,
                    "completed_at": completed_at or scan.completed_at,
                    "error": error or scan.error,
                }
            ).model_dump_json()

    def update_scan_metadata(self, scan_id: str, metadata: dict[str, object]) -> None:
        with session_scope(self.engine) as session:
            record = _get_scan_record(session, scan_id)
            scan = Scan.model_validate_json(record.scan_json)
            updated_metadata = {**scan.metadata, **metadata}
            record.scan_json = scan.model_copy(
                update={"metadata": updated_metadata}
            ).model_dump_json()

    def append_event(self, event: WorkflowEvent) -> None:
        with session_scope(self.engine) as session:
            record = _get_scan_record(session, event.scan_id)
            record.event_count += 1
            session.add(
                WorkflowEventRecord(
                    id=event.id,
                    scan_id=event.scan_id,
                    workspace_id=event.workspace_id,
                    event_type=event.event_type,
                    payload_json=json.dumps(event.payload, sort_keys=True),
                    created_at=_encode_datetime(event.created_at),
                )
            )

    def load_events(self, scan_id: str) -> list[WorkflowEvent]:
        with session_scope(self.engine) as session:
            records = (
                session.query(WorkflowEventRecord)
                .filter(WorkflowEventRecord.scan_id == scan_id)
                .order_by(WorkflowEventRecord.created_at)
                .all()
            )
            return [
                WorkflowEvent(
                    id=r.id,
                    scan_id=r.scan_id,
                    workspace_id=r.workspace_id,
                    event_type=r.event_type,
                    payload=json.loads(r.payload_json) if r.payload_json else {},
                    created_at=_decode_datetime(r.created_at),
                )
                for r in records
            ]

    def save_artifact_ref(self, scan_id: str, artifact_ref: ArtifactRef) -> None:
        with session_scope(self.engine) as session:
            session.add(
                ArtifactRefRecord(
                    id=artifact_ref.id,
                    scan_id=scan_id,
                    kind=artifact_ref.kind.value,
                    uri=artifact_ref.uri,
                    artifact_json=artifact_ref.model_dump_json(),
                )
            )

    def save_candidate_finding(self, finding: CandidateFinding) -> None:
        with session_scope(self.engine) as session:
            # merge (upsert by (scan_id, id)) so re-running a stage on resume is idempotent.
            session.merge(
                CandidateFindingRecord(
                    id=finding.id,
                    scan_id=finding.scan_id,
                    workspace_id=finding.workspace_id,
                    title=finding.title,
                    vuln_class=finding.vuln_class.value,
                    finding_json=finding.model_dump_json(),
                )
            )

    def save_attack_surface_items(self, items: list[AttackSurfaceItem]) -> None:
        with session_scope(self.engine) as session:
            for item in items:
                session.add(
                    AttackSurfaceItemRecord(
                        id=item.id,
                        scan_id=item.scan_id,
                        route=item.route,
                        method=item.method,
                        handler_file=item.handler_file,
                        item_json=item.model_dump_json(),
                    )
                )

    def load_attack_surface_items(self, scan_id: str) -> list[AttackSurfaceItem]:
        with session_scope(self.engine) as session:
            records = session.scalars(
                select(AttackSurfaceItemRecord).where(AttackSurfaceItemRecord.scan_id == scan_id)
            ).all()
            return [AttackSurfaceItem.model_validate_json(record.item_json) for record in records]

    def save_report(self, report: Report, report_path: Path | str) -> None:
        with session_scope(self.engine) as session:
            session.add(
                ReportRecord(
                    id=report.id,
                    scan_id=report.scan_id,
                    workspace_id=report.workspace_id,
                    report_path=str(report_path),
                    report_json=report.model_dump_json(),
                )
            )
            record = _get_scan_record(session, report.scan_id)
            record.report_path = str(report_path)

    def scan_exists(self, scan_id: str) -> bool:
        with session_scope(self.engine) as session:
            return session.get(ScanRecord, scan_id) is not None

    def load_scan(self, scan_id: str) -> Scan:
        with session_scope(self.engine) as session:
            return Scan.model_validate_json(_get_scan_record(session, scan_id).scan_json)

    def load_candidate_findings(self, scan_id: str) -> list[CandidateFinding]:
        with session_scope(self.engine) as session:
            records = session.scalars(
                select(CandidateFindingRecord).where(CandidateFindingRecord.scan_id == scan_id)
            ).all()
            return [CandidateFinding.model_validate_json(record.finding_json) for record in records]

    def save_final_finding(self, finding: FinalFinding) -> None:
        with session_scope(self.engine) as session:
            # merge (upsert by (scan_id, id)) so re-running a stage on resume is idempotent.
            session.merge(
                FinalFindingRecord(
                    id=finding.id,
                    scan_id=finding.scan_id,
                    workspace_id=finding.workspace_id,
                    fingerprint=finding.fingerprint,
                    vuln_class=finding.vuln_class.value,
                    severity=finding.severity.value,
                    title=finding.title,
                    finding_json=finding.model_dump_json(),
                )
            )

    def load_final_findings(self, scan_id: str) -> list[FinalFinding]:
        with session_scope(self.engine) as session:
            records = session.scalars(
                select(FinalFindingRecord).where(FinalFindingRecord.scan_id == scan_id)
            ).all()
            return [FinalFinding.model_validate_json(record.finding_json) for record in records]

    def save_integration_run(self, run: IntegrationRun) -> None:
        with session_scope(self.engine) as session:
            # merge (upsert by idempotency_key) so resumed/repeat delivery is idempotent.
            session.merge(
                IntegrationRunRecord(
                    idempotency_key=run.idempotency_key,
                    scan_id=run.scan_id,
                    sink=run.sink,
                    status=run.status.value,
                    run_json=run.model_dump_json(),
                )
            )

    def load_integration_runs(self, scan_id: str) -> list[IntegrationRun]:
        with session_scope(self.engine) as session:
            records = session.scalars(
                select(IntegrationRunRecord).where(IntegrationRunRecord.scan_id == scan_id)
            ).all()
            return [IntegrationRun.model_validate_json(record.run_json) for record in records]

    def save_scan_manifest(self, manifest: ScanManifest) -> None:
        with session_scope(self.engine) as session:
            session.merge(
                ScanManifestRecord(
                    scan_id=manifest.scan_id,
                    manifest_json=manifest.model_dump_json(),
                )
            )

    def load_scan_manifest(self, scan_id: str) -> ScanManifest | None:
        with session_scope(self.engine) as session:
            record = session.get(ScanManifestRecord, scan_id)
            if record is None:
                return None
            return ScanManifest.model_validate_json(record.manifest_json)

    def save_architecture_doc(self, scan_id: str, doc: ArchitectureDoc) -> None:
        with session_scope(self.engine) as session:
            session.merge(
                ArchitectureDocRecord(
                    scan_id=scan_id,
                    doc_json=doc.model_dump_json(),
                )
            )

    def load_architecture_doc(self, scan_id: str) -> ArchitectureDoc | None:
        with session_scope(self.engine) as session:
            record = session.get(ArchitectureDocRecord, scan_id)
            if record is None:
                return None
            return ArchitectureDoc.model_validate_json(record.doc_json)

    def save_tool_invocation(self, invocation: ToolInvocation) -> None:
        with session_scope(self.engine) as session:
            session.merge(
                ToolInvocationRecord(
                    id=invocation.id,
                    scan_id=invocation.scan_id,
                    tool_name=invocation.tool_name,
                    invocation_json=invocation.model_dump_json(),
                )
            )

    def load_tool_invocations(self, scan_id: str) -> list[ToolInvocation]:
        with session_scope(self.engine) as session:
            records = session.scalars(
                select(ToolInvocationRecord).where(ToolInvocationRecord.scan_id == scan_id)
            ).all()
            return [
                ToolInvocation.model_validate_json(record.invocation_json) for record in records
            ]

    def save_model_invocation(self, invocation: ModelInvocation) -> None:
        with session_scope(self.engine) as session:
            session.merge(
                ModelInvocationRecord(
                    id=invocation.id,
                    scan_id=invocation.scan_id,
                    role=invocation.role,
                    invocation_json=invocation.model_dump_json(),
                )
            )

    def load_model_invocations(self, scan_id: str) -> list[ModelInvocation]:
        with session_scope(self.engine) as session:
            records = session.scalars(
                select(ModelInvocationRecord).where(ModelInvocationRecord.scan_id == scan_id)
            ).all()
            return [
                ModelInvocation.model_validate_json(record.invocation_json) for record in records
            ]

    def list_scan_summaries(self) -> list[ScanSummary]:
        with session_scope(self.engine) as session:
            records = session.scalars(
                select(ScanRecord).order_by(ScanRecord.created_at.desc())
            ).all()
            return [
                ScanSummary(
                    scan_id=record.id,
                    repo_path=record.target_repo_path,
                    status=record.status,
                    profile_id=record.profile_id,
                    event_count=record.event_count,
                    report_path=record.report_path,
                    created_at=record.created_at,
                    completed_at=record.completed_at,
                    error=record.error,
                )
                for record in records
            ]


def _get_scan_record(session: Session, scan_id: str) -> ScanRecord:
    record = session.get(ScanRecord, scan_id)
    if record is None:
        msg = f"Unknown scan id: {scan_id}"
        raise ValueError(msg)
    return record


def _encode_optional_datetime(value: datetime | None) -> str | None:
    return _encode_datetime(value) if value is not None else None


def _encode_datetime(value: datetime) -> str:
    return value.isoformat()


def _decode_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)
