"""Quarry configuration management."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class QuarrySettings(BaseSettings):
    """Configuration for Quarry application.

    Environment variables are prefixed with QUARRY_ and override defaults.
    For example, QUARRY_TEMPORAL_ADDRESS overrides temporal_address.
    """

    model_config = SettingsConfigDict(env_prefix="QUARRY_")

    server_url: str = "http://localhost:8000"
    temporal_address: str = "localhost:7233"
    task_queue: str = "quarry-control"
    server_host: str = "127.0.0.1"
    server_port: int = 8000
    server_no_worker: bool = False
    db_path: str = ".quarry/quarry.db"

    # Model layer. Field names avoid a leading ``model_`` (pydantic's protected
    # namespace). Empty defaults fall back to the role-based panel.
    default_provider: str = ""
    default_model: str = ""
    prompt_retention: str = "metadata_only"
    redaction_enabled: bool = True
