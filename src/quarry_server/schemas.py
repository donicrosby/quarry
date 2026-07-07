"""Request and response schemas for the Quarry server API."""

from pydantic import BaseModel, ConfigDict, Field

from quarry.schemas import VulnerabilityClass


def _empty_server_vuln_classes() -> list[VulnerabilityClass]:
    return []


class StartScanRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    # Optional git URL to clone (public/token-HTTPS/SSH). When set, the clone's
    # local path becomes the effective repo path for the scan.
    repo_url: str | None = None
    target_url: str | None = None
    output_dir: str = ".quarry"
    db_path: str = ".quarry/quarry.db"
    vuln_classes: list[VulnerabilityClass] = Field(default_factory=_empty_server_vuln_classes)
    # Live dynamic validation flags (ADR-017). CLI gates are authoritative;
    # target_url presence alone must NOT enable live validation.
    dynamic_validation_enabled: bool = False
    live_prove_enabled: bool = False
    # AuthProfileSet serialized as JSON; None = unauthenticated.
    auth_profiles_json: str | None = None
    # True for benchmark scoring runs: forces integrations off (no lifecycle
    # hook or sink fires), regardless of quarry.toml [integrations.*].
    benchmark: bool = False


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
