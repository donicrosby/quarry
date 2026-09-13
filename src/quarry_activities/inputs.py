"""Temporal activity input payloads.

These Pydantic models intentionally use JSON-serializable primitive fields at the
Temporal boundary. Activities convert strings back to richer domain objects or
``Path`` instances internally.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from quarry.schemas import ChangedFile


class CreateSnapshotInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    scan_id: str
    artifact_root: str
    workspace_id: str = "local"


class CloneRepoInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_url: str
    dest_dir: str
    # When set, the clone is checked out at exactly this commit (deterministic
    # re-clone on retries/resumes). When None, the activity captures HEAD's SHA.
    pinned_sha: str | None = None


class CloneRepoResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    local_path: str
    commit_sha: str


class GitDiffInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    base_commit: str
    head_commit: str
    scan_id: str = ""
    workspace_id: str = "local"


class MapRegionsInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    changed_files: tuple[ChangedFile, ...]


class ScanSecretsInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_root: str
    file_paths: tuple[str, ...] | None = None


class RunDiffScanInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_id: str
    repo_path: str
    base_commit: str
    head_commit: str
    db_path: str = ".quarry/quarry.db"
    output_dir: str = ".quarry"
    target_url: str = ""


class ValidateCandidateInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_json: str
    allowlist: list[str] | None = None


class PromoteFindingInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_json: str
    validation_json: str


class BuildCoverageLedgerInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_id: str
    artifact_root: str
    requested_vuln_classes: tuple[str, ...]
    completed_vuln_classes: tuple[str, ...]
    agent_tasks_total: int
    agent_tasks_scanned: int
    skipped_json: str
    workspace_id: str = "local"


class BuildCoverageLedgerOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    ledger_json: str
    artifact_ref_json: str


class RenderReportInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_json: str
    findings_json: str
    snapshot_json: str | None
    final_findings_json: str | None
    report_path: str | None = None
    coverage_json: str | None = None
    proof_artifacts_json: str | None = None
    manifest_json: str | None = None
    model_invocations_json: str | None = None
    # Findings retained pending proof (status=NEEDS_PROOF); rendered as Unverified section.
    needs_proof_findings_json: str | None = None
    # Why the ADR-022 coverage loop ended: "budget" | "convergence" |
    # "finding_plateau" | "round_cap". Rendered in the Coverage section so an early
    # stop on diminishing yield is distinguishable from exhausting the round cap.
    coverage_stop_reason: str | None = None


class DeliverIntegrationsInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_id: str
    final_findings_json: str
    artifact_root: str
    workspace_id: str = "local"
    dry_run: bool = True
    existing_keys: tuple[str, ...] = ()


class DispatchLifecycleHooksInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_type: str
    scan_id: str
    artifact_root: str
    workspace_id: str = "local"
    # A FinalFinding, serialized as JSON; None for finding-less events.
    finding_json: str | None = None
    # Severity value string (e.g. "critical"); None for finding-less events.
    severity: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True
    existing_keys: tuple[str, ...] = ()
    # list[IntegrationConfig], serialized as JSON — resolved from
    # Scan.profile.integration_configs by the caller.
    integration_configs_json: str = "[]"


class BuildScanManifestInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_id: str
    profile_id: str
    repo_path: str
    workspace_id: str = "local"
    plugins_active: tuple[str, ...] = ()


class RenderReportOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    report_text: str
    report_path: str
    report_ref_json: str


class PersistScanStateInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    db_path: str
    operation: str
    payload_json: str


class HttpRequestActivityInput(BaseModel):
    """Input payload for http_request_activity (ADR-017, Layer 6).

    All values are JSON-serializable primitives at the Temporal boundary.
    Richer domain objects are reconstructed inside the activity.
    """

    model_config = ConfigDict(frozen=True)

    spec_json: str  # HttpRequestSpec serialized
    target_endpoint_json: str  # TargetEndpoint serialized
    allowed_hosts: tuple[str, ...]  # independent Layer-6 enforcement
    artifact_store_path: str  # path for LocalArtifactStore
    scan_id: str
    candidate_finding_id: str
    auth_profile_set_json: str | None = None  # AuthProfileSet serialized; None = unauthenticated


class ReadArtifactTextInput(BaseModel):
    """Input payload for read_artifact_text_activity (registry wiring).

    Resolves one artifact by store KEY (not the uuid ArtifactRef id) from the
    scan's store rooted at ``artifact_store_path / scan_id`` — the same
    namespace convention as ``http-request``.  All values are primitives.
    """

    model_config = ConfigDict(frozen=True)

    artifact_store_path: str
    scan_id: str
    artifact_key: str


class SandboxExecActivityInput(BaseModel):
    """Input payload for sandbox_exec_activity (ADR-017 §5 — transport-agnostic prove).

    Mirrors HttpRequestActivityInput: all values are JSON-serializable primitives at the
    Temporal boundary.  Richer domain objects (SandboxExecSpec, TargetEndpoint,
    ProveCorpus, AuthProfileSet) are reconstructed inside the activity.
    target_endpoint_json is None for CLI-only prove (no network egress).
    """

    model_config = ConfigDict(frozen=True)

    spec_json: str  # SandboxExecSpec serialized
    target_endpoint_json: str | None  # TargetEndpoint serialized; None = no-network (CLI prove)
    allowed_hosts: tuple[str, ...]  # independent Layer-6 enforcement (empty for CLI prove)
    artifact_store_path: str  # path for LocalArtifactStore
    scan_id: str
    candidate_finding_id: str
    auth_profile_set_json: str | None = None  # AuthProfileSet serialized; None = unauthenticated
    prove_corpus_json: str | None = None  # ProveCorpus serialized; None = HTTP prove
