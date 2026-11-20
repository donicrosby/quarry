"""Quarry configuration management."""

from pydantic import Field
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

    # Network-backend tuning (ADR-024 §B).
    # Max artifact size the Redis backend will accept (larger -> ValueError, use S3).
    redis_max_artifact_bytes: int = 1_048_576  # env: QUARRY_REDIS_MAX_ARTIFACT_BYTES
    # Bounded retry for transient network failures on put_bytes/get_bytes.
    artifact_retry_max_attempts: int = 3  # env: QUARRY_ARTIFACT_RETRY_MAX_ATTEMPTS
    artifact_retry_backoff_seconds: float = 1.0  # env: QUARRY_ARTIFACT_RETRY_BACKOFF_SECONDS

    # Sandbox execution backend (ADR-022 §A).
    # "" or "local"     => LocalSubprocessSandbox (default, dev/test, no Docker required).
    # "container"       => ContainerSandbox Tier 2 (Docker/Podman, production default).
    # "k8s_job"         => K8sJobSandbox Tier 3 (deferred; multi-tenant only).
    sandbox_backend: str = ""  # env: QUARRY_SANDBOX_BACKEND
    sandbox_image: str = ""  # env: QUARRY_SANDBOX_IMAGE (override default container image)
    # Container memory cap for the Tier-2 sandbox (Docker ``--memory`` value,
    # e.g. "2g").  Empty => the backend default (DEFAULT_MEMORY_LIMIT).  A
    # browser-capable worker executing untrusted page JS must be capped so a
    # runaway Chromium is OOM-killed rather than starving the host.
    # env: QUARRY_SANDBOX_MEMORY
    sandbox_memory: str = ""

    # SSRF/XXE canary sidecar (Tier 2).  The canary listener must be published on
    # a single pinned host interface the target can reach — never a wildcard.
    # Empty means no Tier-2 canary (the listener fails closed).  env: QUARRY_CANARY_HOST
    canary_host: str = ""
    canary_image: str = ""  # env: QUARRY_CANARY_IMAGE (override default canary image)
    # Dependency-manifest supply-chain scanner. Configurable typosquat name
    # patterns; the check is a no-op until at least one pattern is configured.
    # env: QUARRY_TYPOSQUAT_PATTERNS (JSON array, e.g. '["dateutil","lodassh"]')
    typosquat_patterns: list[str] = Field(default_factory=list)
    # Proof-artifact quarantine (D6 / proof-artifact-quarantine). Per-kind size
    # limits in bytes, enforced before any artifact byte is accepted; the default
    # covers kinds without an explicit limit. A quarantined proof artifact is
    # local-only unless quarantine_remote_backend names the one remote backend the
    # operator has explicitly opted in as a quarantine destination.
    quarantine_max_tool_output_bytes: int = 1_048_576
    # env: QUARRY_QUARANTINE_MAX_TOOL_OUTPUT_BYTES
    quarantine_max_http_response_bytes: int = 104_857_600
    # env: QUARRY_QUARANTINE_MAX_HTTP_RESPONSE_BYTES
    quarantine_max_code_snippet_bytes: int = 5_242_880
    # env: QUARRY_QUARANTINE_MAX_CODE_SNIPPET_BYTES
    quarantine_max_artifact_bytes: int = 104_857_600
    # env: QUARRY_QUARANTINE_MAX_ARTIFACT_BYTES
    quarantine_remote_backend: str = ""  # env: QUARRY_QUARANTINE_REMOTE_BACKEND
    malware_scanner: str = ""  # env: QUARRY_MALWARE_SCANNER ("" = no scanner configured)

    # SSRF/XXE canary sidecar (Tier 2).  The canary listener must be published on
    # a single pinned host interface the target can reach — never a wildcard.
    # Empty means no Tier-2 canary (the listener fails closed).  env: QUARRY_CANARY_HOST
    canary_host: str = ""
    canary_image: str = ""  # env: QUARRY_CANARY_IMAGE (override default canary image)

    # Traffic-capture recording proxy + verified evidence store
    # (traffic-capture-verified-evidence). The capture root is the shared volume
    # the mitmproxy sidecar writes and the worker-side evidence snapshot reads;
    # the evidence root is the durable store (never reclaimed with capture).
    traffic_capture_root: str = ".quarry/traffic-capture"
    # env: QUARRY_TRAFFIC_CAPTURE_ROOT
    evidence_store_root: str = ".quarry/evidence"
    # env: QUARRY_EVIDENCE_STORE_ROOT
    traffic_capture_max_bytes: int = 2_147_483_648
    # env: QUARRY_TRAFFIC_CAPTURE_MAX_BYTES
