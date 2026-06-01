"""Temporal activity input payloads.

These Pydantic models intentionally use JSON-serializable primitive fields at the
Temporal boundary. Activities convert strings back to richer domain objects or
``Path`` instances internally.
"""

from pydantic import BaseModel, ConfigDict

from quarry.schemas import ChangedFile


class CreateSnapshotInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    scan_id: str
    artifact_root: str
    workspace_id: str = "local"


class ExtractRoutesInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    file_path: str


class ExtractRoutesForRepoInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    scan_id: str


class GitDiffInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    base_commit: str
    head_commit: str


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


class RenderReportInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_json: str
    findings_json: str
    snapshot_json: str | None
    attack_surface_json: str | None
    final_findings_json: str | None
    report_path: str | None = None


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
