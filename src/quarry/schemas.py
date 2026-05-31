"""Quarry domain schemas."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


class ScanStatus(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    PREPARING = "preparing"
    MAPPING = "mapping"
    SCANNING = "scanning"
    VALIDATING = "validating"
    PROVING = "proving"
    REPORTING = "reporting"
    INTEGRATING = "integrating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    VALIDATING = "validating"
    REJECTED = "rejected"
    VALIDATED = "validated"
    PROVING = "proving"
    PROVED = "proved"
    FINAL = "final"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VulnerabilityClass(StrEnum):
    SECRETS = "secrets"
    IDOR = "idor"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    FILE_UPLOAD = "file_upload"


class ArtifactKind(StrEnum):
    REPO_MANIFEST = "repo_manifest"
    CODE_SNIPPET = "code_snippet"
    ATTACK_SURFACE = "attack_surface"
    TOOL_STDOUT = "tool_stdout"
    TOOL_STDERR = "tool_stderr"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    MODEL_PROMPT = "model_prompt"
    MODEL_RESPONSE = "model_response"
    REPORT = "report"
    INTEGRATION_PAYLOAD = "integration_payload"


class RedactionStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    REDACTED = "redacted"
    CONTAINS_SENSITIVE = "contains_sensitive"
    UNKNOWN = "unknown"


def _empty_source_refs() -> list["SourceRef"]:
    return []


def _empty_artifact_refs() -> list["ArtifactRef"]:
    return []


def _empty_strings() -> list[str]:
    return []


class SourceRef(BaseModel):
    artifact_ref: str | None = None
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    symbol: str | None = None
    snippet_hash: str | None = None


class ArtifactRef(BaseModel):
    id: str
    uri: str
    kind: ArtifactKind
    content_type: str
    sha256: str
    size_bytes: int
    redaction_status: RedactionStatus = RedactionStatus.UNKNOWN
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class FileManifestEntry(BaseModel):
    path: str
    size_bytes: int
    sha256: str
    language: str | None = None
    ignored: bool = False
    ignore_reason: str | None = None


class FileManifest(BaseModel):
    entries: list[FileManifestEntry]
    total_size_bytes: int


class RepositorySnapshot(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    repo_path: str
    commit_sha: str | None = None
    file_manifest_ref: ArtifactRef
    file_count: int
    total_size_bytes: int
    detected_frameworks: list[str] = Field(default_factory=_empty_strings)
    ignored_paths: list[str] = Field(default_factory=_empty_strings)
    created_at: datetime


class CodeIndex(BaseModel):
    id: str
    scan_id: str
    snapshot_id: str
    symbols_ref: ArtifactRef | None = None
    routes_ref: ArtifactRef | None = None
    imports_ref: ArtifactRef | None = None
    dependencies_ref: ArtifactRef | None = None
    created_at: datetime


class AttackSurfaceItem(BaseModel):
    id: str
    scan_id: str
    route: str
    method: str
    handler_file: str
    handler_symbol: str | None = None
    params: list[str] = Field(default_factory=_empty_strings)
    auth_required: bool | None = None
    auth_hint: str | None = None
    source_refs: list[SourceRef] = Field(default_factory=_empty_source_refs)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Workspace(BaseModel):
    id: str
    name: str
    created_at: datetime


class Hunter(BaseModel):
    id: str
    email: str | None = None
    display_name: str
    role: str = "local_admin"


class Target(BaseModel):
    id: str
    workspace_id: str
    repo_path: str
    target_url: str | None = None
    target_kind: Literal["local_repo", "local_web_app", "remote_web_app"] = "local_repo"
    allowed_hosts: list[str] = Field(default_factory=list)
    auth_config_ref: str | None = None
    created_at: datetime


class TargetAuthorization(BaseModel):
    id: str
    target_id: str
    workspace_id: str
    authorized_by: str
    allowed_hosts: list[str]
    allowed_repo_paths: list[str]
    expires_at: datetime | None = None
    notes: str | None = None
    created_at: datetime


class ScanProfile(BaseModel):
    id: str
    name: str
    vuln_classes: list[VulnerabilityClass]
    max_depth: int = 1
    dynamic_validation_enabled: bool = False
    proof_enabled: bool = False
    model_assist_enabled: bool = False
    integrations_enabled: bool = False
    dry_run_integrations: bool = True
    max_runtime_seconds: int = 1800


class Scan(BaseModel):
    id: str
    workspace_id: str
    target_id: str
    requested_by: str
    profile: ScanProfile
    status: ScanStatus
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CandidateFinding(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    vuln_class: VulnerabilityClass
    title: str
    hypothesis: str
    affected_component: str | None = None
    attack_surface_item_id: str | None = None
    source_refs: list[SourceRef] = Field(default_factory=_empty_source_refs)
    evidence_refs: list[ArtifactRef] = Field(default_factory=_empty_artifact_refs)
    confidence: Confidence = Confidence.LOW
    status: FindingStatus = FindingStatus.CANDIDATE
    created_by: str
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class FinalFinding(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    fingerprint: str
    vuln_class: VulnerabilityClass
    severity: Severity
    title: str
    summary: str
    affected_component: str | None = None
    attack_surface_item_id: str | None = None
    source_refs: list[SourceRef] = Field(default_factory=_empty_source_refs)
    validation_result_id: str
    proof_artifact_ids: list[str] = Field(default_factory=_empty_strings)
    remediation: str | None = None
    created_at: datetime


class Report(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    title: str
    summary: str
    finding_ids: list[str]
    formats: list[str]
    artifact_refs: list[ArtifactRef]
    generated_at: datetime


class WorkflowEvent(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


def local_scan_profile() -> ScanProfile:
    return ScanProfile(
        id="local-fast",
        name="Local Fast",
        vuln_classes=[VulnerabilityClass.SECRETS],
    )
