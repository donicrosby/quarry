"""Request and response schemas for the Quarry server API."""

from pydantic import BaseModel, ConfigDict, Field

from quarry.schemas import VulnerabilityClass


def _empty_server_vuln_classes() -> list[VulnerabilityClass]:
    return []


class StartScanRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    target_url: str | None = None
    output_dir: str = ".quarry"
    db_path: str = ".quarry/quarry.db"
    vuln_classes: list[VulnerabilityClass] = Field(default_factory=_empty_server_vuln_classes)


class DiffScanRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    base_commit: str
    head_commit: str
    target_url: str = ""
    output_dir: str = ".quarry"
    db_path: str = ".quarry/quarry.db"


class ScanResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_id: str
    status: str
