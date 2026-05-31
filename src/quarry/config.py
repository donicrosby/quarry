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
    db_path: str = ".quarry/quarry.db"
