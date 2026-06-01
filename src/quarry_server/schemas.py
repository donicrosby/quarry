"""Request and response schemas for the Quarry server API."""

from pydantic import BaseModel, ConfigDict


class StartScanRequest(BaseModel):
    """Request body for starting a scan workflow."""

    model_config = ConfigDict(frozen=True)

    repo_path: str
    target_url: str | None = None
    output_dir: str = ".quarry"
    db_path: str = ".quarry/quarry.db"


class ScanResponse(BaseModel):
    """Response returned after a scan workflow is started."""

    model_config = ConfigDict(frozen=True)

    scan_id: str
    status: str
