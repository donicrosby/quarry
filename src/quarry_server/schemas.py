"""Request and response schemas for the Quarry server API."""

from pydantic import BaseModel, ConfigDict


class StartScanRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    target_url: str | None = None
    output_dir: str = ".quarry"
    db_path: str = ".quarry/quarry.db"


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
