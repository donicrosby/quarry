import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import ForeignKey, Integer, String, Text, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapped, Session, mapped_column

from quarry.schemas import (
    ArtifactRef,
    AttackSurfaceItem,
    CandidateFinding,
    FinalFinding,
    Report,
    Scan,
    ScanStatus,
    Target,
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

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
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

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    workspace_id: Mapped[str] = mapped_column(String, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    vuln_class: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    finding_json: Mapped[str] = mapped_column(Text, nullable=False)


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
    ) -> None:
        with session_scope(self.engine) as session:
            record = _get_scan_record(session, scan_id)
            scan = Scan.model_validate_json(record.scan_json)
            record.status = status.value
            record.started_at = _encode_optional_datetime(started_at) or record.started_at
            record.completed_at = _encode_optional_datetime(completed_at) or record.completed_at
            if report_path is not None:
                record.report_path = str(report_path)
            record.scan_json = scan.model_copy(
                update={
                    "status": status,
                    "started_at": started_at or scan.started_at,
                    "completed_at": completed_at or scan.completed_at,
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
            session.add(
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
            session.add(
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
