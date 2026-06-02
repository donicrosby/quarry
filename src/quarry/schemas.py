"""Quarry domain schemas."""

from __future__ import annotations

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


class TriageLabel(StrEnum):
    TP = "tp"
    FP = "fp"
    DUP = "dup"
    OOS = "oos"


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
    COVERAGE_LEDGER = "coverage_ledger"


class RedactionStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    REDACTED = "redacted"
    CONTAINS_SENSITIVE = "contains_sensitive"
    UNKNOWN = "unknown"


def _empty_source_refs() -> list[SourceRef]:
    return []


def _empty_artifact_refs() -> list[ArtifactRef]:
    return []


def _empty_strings() -> list[str]:
    return []


def _empty_panel_entries() -> list[ModelPanelEntry]:
    return []


def _empty_vuln_classes() -> list[VulnerabilityClass]:
    return []


def _empty_coverage_gaps() -> list[CoverageGap]:
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
    entry_points: list[str] = Field(default_factory=_empty_strings)
    repo_type: str | None = None
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


class ModelPanelEntry(BaseModel):
    id: str
    scan_id: str
    role: str
    provider: str
    model: str
    rate_limit_rpm: int = 30


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
    plugins_active: list[str] = Field(default_factory=_empty_strings)


class Scan(BaseModel):
    id: str
    workspace_id: str
    target_id: str
    requested_by: str
    profile: ScanProfile
    status: ScanStatus
    parent_scan_id: str | None = None
    budget_cap_usd: float | None = None
    panel_snapshot: list[ModelPanelEntry] = Field(default_factory=_empty_panel_entries)
    attack_classes: list[VulnerabilityClass] = Field(default_factory=_empty_vuln_classes)
    plugins_active: list[str] = Field(default_factory=_empty_strings)
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanSummary(BaseModel):
    scan_id: str
    repo_path: str
    status: str
    profile_id: str
    event_count: int
    report_path: str | None = None
    created_at: str
    completed_at: str | None = None


class CandidateFinding(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    vuln_class: VulnerabilityClass
    title: str
    hypothesis: str
    reasoning: str | None = None
    affected_component: str | None = None
    attack_surface_item_id: str | None = None
    source_refs: list[SourceRef] = Field(default_factory=_empty_source_refs)
    evidence_refs: list[ArtifactRef] = Field(default_factory=_empty_artifact_refs)
    confidence: Confidence = Confidence.LOW
    severity: Severity = Severity.MEDIUM
    severity_adjusted: Severity | None = None
    status: FindingStatus = FindingStatus.CANDIDATE
    root_cause_key: str | None = None
    cross_vendor_disagreement: bool = False
    trigger_input: str | None = None
    scrubber_hits: int = 0
    triage_label: TriageLabel | None = None
    triage_notes: str | None = None
    triaged_at: datetime | None = None
    duplicate_of: str | None = None
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
    severity_adjusted: Severity | None = None
    title: str
    summary: str
    affected_component: str | None = None
    attack_surface_item_id: str | None = None
    source_refs: list[SourceRef] = Field(default_factory=_empty_source_refs)
    validation_result_id: str
    proof_artifact_ids: list[str] = Field(default_factory=_empty_strings)
    trace_id: str | None = None
    triage_label: TriageLabel | None = None
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


class AgentTask(BaseModel):
    id: str
    scan_id: str
    role: str
    task_name: str
    vuln_class: VulnerabilityClass | None = None
    scope: str | None = None
    source: Literal["recon", "gapfill", "feedback"] = "recon"
    gapfill_pass: int = 0
    input_refs: list[ArtifactRef] = Field(default_factory=_empty_artifact_refs)
    output_refs: list[ArtifactRef] = Field(default_factory=_empty_artifact_refs)
    status: str
    created_at: datetime
    completed_at: datetime | None = None
    error: str | None = None


class ValidationResult(BaseModel):
    id: str
    candidate_finding_id: str
    scan_id: str
    verdict: Literal["validated", "rejected", "needs_proof", "inconclusive"]
    reasons: list[str] = Field(default_factory=_empty_strings)
    checks_run: list[str] = Field(default_factory=_empty_strings)
    evidence_refs: list[ArtifactRef] = Field(default_factory=_empty_artifact_refs)
    model_invocation_id: str | None = None
    cross_vendor: bool = False
    created_at: datetime


class ProofArtifact(BaseModel):
    id: str
    scan_id: str
    candidate_finding_id: str
    final_finding_id: str | None = None
    proof_type: str
    description: str
    evidence_refs: list[ArtifactRef] = Field(default_factory=_empty_artifact_refs)
    safe_payload: str | None = None
    redaction_status: RedactionStatus
    created_at: datetime


class GapfillTask(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    vuln_class: VulnerabilityClass
    scope: str
    reason: str
    nudge_prompt_hint: str | None = None
    gapfill_pass: int = 1
    parent_task_id: str | None = None
    status: str = "pending"
    created_at: datetime


class CoverageGap(BaseModel):
    id: str
    scan_id: str
    attack_surface_item_id: str | None = None
    vuln_class: VulnerabilityClass | None = None
    reason: str
    recommended_next_task: str | None = None
    severity_hint: str | None = None


class CoverageLedger(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    attack_surface_items_total: int
    attack_surface_items_scanned: int
    vuln_classes_requested: list[VulnerabilityClass] = Field(default_factory=_empty_vuln_classes)
    vuln_classes_completed: list[VulnerabilityClass] = Field(default_factory=_empty_vuln_classes)
    skipped_items: list[CoverageGap] = Field(default_factory=_empty_coverage_gaps)
    created_at: datetime


class GroundTruthFinding(BaseModel):
    id: str
    vuln_class: VulnerabilityClass
    file_path: str
    route: str | None = None
    severity: Severity
    expected_fingerprint_hint: str | None = None


class BenchmarkCase(BaseModel):
    id: str
    name: str
    repo_path: str
    target_url: str | None = None
    ground_truth_ref: ArtifactRef
    scan_profile_id: str


class ModelInvocation(BaseModel):
    id: str
    scan_id: str
    workspace_id: str
    task_name: str
    role: str
    provider: str
    model: str
    prompt_version: str
    prompt_hash: str
    temperature: float = 0.0
    prompt_ref: ArtifactRef | None = None
    response_ref: ArtifactRef | None = None
    token_input: int | None = None
    token_output: int | None = None
    cached_tokens: int | None = None
    estimated_cost: float | None = None
    scrubber_hits: int = 0
    redaction_status: RedactionStatus = RedactionStatus.UNKNOWN
    created_at: datetime


class BudgetPolicy(BaseModel):
    id: str
    workspace_id: str
    max_cost_per_scan: float | None = None
    max_tokens_per_scan: int | None = None
    max_model_calls_per_stage: int | None = None
    max_concurrent_scans: int = 1
    max_runtime_seconds: int = 1800


class DiffLabel(StrEnum):
    INTRODUCED_BY_DIFF = "introduced_by_diff"
    TOUCHED_BY_DIFF = "touched_by_diff"
    POSSIBLY_EXPOSED_BY_DIFF = "possibly_exposed_by_diff"
    UNCHANGED = "unchanged"


class ChangedFile(BaseModel):
    path: str
    status: str
    additions: int = 0
    deletions: int = 0
    hunks: list[str] = Field(default_factory=list)


class ImpactedCodeRegion(BaseModel):
    file_path: str
    start_line: int
    end_line: int
    label: DiffLabel
    scope_name: str | None = None
    scope_type: str | None = None


def _empty_changed_files() -> list[ChangedFile]:
    return []


def _empty_impacted_regions() -> list[ImpactedCodeRegion]:
    return []


class GitDiff(BaseModel):
    base_commit: str
    head_commit: str
    changed_files: list[ChangedFile] = Field(default_factory=_empty_changed_files)
    total_additions: int = 0
    total_deletions: int = 0


class DiffScanInput(BaseModel):
    repo_path: str
    base_commit: str
    head_commit: str
    db_path: str
    target_url: str | None = None


class DiffScanResult(BaseModel):
    scan_id: str
    git_diff: GitDiff
    impacted_regions: list[ImpactedCodeRegion] = Field(default_factory=_empty_impacted_regions)
    candidate_finding_count: int = 0
    final_finding_count: int = 0


def local_scan_profile() -> ScanProfile:
    return ScanProfile(
        id="local-fast",
        name="Local Fast",
        vuln_classes=[VulnerabilityClass.SECRETS],
    )
