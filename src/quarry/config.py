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

    # Adversarial-validation checklist (candidate-precision-and-calibration).
    # When true the validate role's debater runs the negative-constraint
    # checklist refuter; when false it falls back to the legacy binary refuter.
    # env: QUARRY_VALIDATE_CHECKLIST_ENABLED
    validate_checklist_enabled: bool = True

    # quarry.toml panel config
    config_file: str = "quarry.toml"
    panel: str = ""
    focus_classes: str = ""  # comma-separated, env: QUARRY_FOCUS_CLASSES

    # Artifact store backend (Phase 1c / ADR-022 §B).
    # "" or "file" => LocalArtifactStore (default, dev, backward-compatible).
    # "redis" => RedisArtifactStore (deferred; fast small scratch).
    # "s3"    => S3ArtifactStore    (deferred; large blobs, e.g. compiled binaries).
    artifact_backend: str = ""  # env: QUARRY_ARTIFACT_BACKEND
    redis_url: str = ""  # env: QUARRY_REDIS_URL      (used when backend=redis)
    s3_bucket: str = ""  # env: QUARRY_S3_BUCKET      (used when backend=s3)

    # Sandbox execution backend (ADR-022 §A).
    # "" or "local"     => LocalSubprocessSandbox (default, dev/test, no Docker required).
    # "container"       => ContainerSandbox Tier 2 (Docker/Podman, production default).
    # "k8s_job"         => K8sJobSandbox Tier 3 (deferred; multi-tenant only).
    sandbox_backend: str = ""  # env: QUARRY_SANDBOX_BACKEND
    sandbox_image: str = ""  # env: QUARRY_SANDBOX_IMAGE (override default container image)
