"""quarry.toml configuration loader and panel/focus resolver.

Reads the TOML-based multi-model panel configuration, merges named panels over
the built-in DEFAULT_PANEL role-by-role, and resolves the active vulnerability
class focus for a scan.
"""

from __future__ import annotations

import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from quarry.schemas import Provider, Target, TargetAuthorization, VulnerabilityClass


def _empty_vuln_classes() -> list[VulnerabilityClass]:
    return []


# Keys matching this pattern in the raw TOML top level are rejected at parse
# time to prevent secrets from leaking into config files.
_CREDENTIAL_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD|_CREDENTIAL)$")


class RoleConfig(BaseModel):
    """Configuration for one model role in a panel."""

    provider: Provider = Provider.MOCK
    model: str = ""
    rpm: int = 30


# The default built-in panel.  All roles fall back here if not overridden.
DEFAULT_PANEL: dict[str, RoleConfig] = {
    "recon": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "hunt": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "validate": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "gapfill": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "prove": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "trace": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "report": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    # dynamic_validate: live corroboration role (ADR-017). Separate from static
    # validate to keep the network-free adversarial-review boundary intact.
    "dynamic_validate": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
}


class NamedPanel(BaseModel):
    """A named set of role configs that overrides DEFAULT_PANEL role-by-role."""

    roles: dict[str, RoleConfig] = Field(default_factory=dict)


class BudgetConfig(BaseModel):
    """Budget constraints applied globally across scans."""

    max_cost_per_scan_usd: float | None = None
    max_tokens_per_scan: int | None = None


class ScanDefaultsConfig(BaseModel):
    """Defaults applied to every scan unless overridden at the CLI or TUI."""

    focus_classes: list[VulnerabilityClass] = Field(default_factory=_empty_vuln_classes)
    hunt_max_iterations: int = 12
    hunt_max_concurrent: int = 8
    validate_max_iterations: int = 20
    gapfill_max_iterations: int = 20
    recon_max_iterations: int = 40
    dedup_max_iterations: int = 8
    # Optional fixed seed. When None, each scan derives a deterministic seed
    # from its scan_id UUID so runs are reproducible without pinning a global value.
    seed: int | None = None


class RetryConfig(BaseModel):
    """How many times each Temporal activity is attempted before giving up.

    ``max_attempts`` counts the initial try plus retries (Temporal semantics):
    e.g. ``4`` means one attempt + three retries. The default sits in the
    recommended 3–5 range; values below 1 are clamped to 1 (at least one try).
    """

    max_attempts: int = 4

    @field_validator("max_attempts")
    @classmethod
    def _clamp_min_one(cls, v: int) -> int:
        return max(1, v)


class ReasoningLexiconConfig(BaseModel):
    """Custom banned-phrase/evidence lists for the vagueness guard.

    When populated from ``[scan.reasoning_lexicon]`` in quarry.toml, these
    lists are passed to ``check_vague_reasoning`` as the ``banned_phrases``
    and ``banned_evidence`` overrides, replacing the module-level defaults.

    Keep entries short and generic — any phrase that would appear in *vague*
    reasoning but never in *specific* reasoning. Wrong entries silently reject
    valid hunt actions and waste iterations.
    """

    banned_phrases: list[str] = Field(default_factory=list)
    banned_evidence: list[str] = Field(default_factory=list)


class ScanConfig(BaseModel):
    """Per-scan runtime configuration from ``[scan]`` in quarry.toml."""

    reasoning_lexicon: ReasoningLexiconConfig | None = None


class QuarryConfig(BaseModel):
    """Top-level parsed quarry.toml configuration."""

    panels: dict[str, NamedPanel] = Field(default_factory=dict)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    scan_defaults: ScanDefaultsConfig = Field(default_factory=ScanDefaultsConfig)
    retry: RetryConfig = Field(default_factory=RetryConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)


def _check_for_credentials(raw: dict[str, Any]) -> None:
    """Raise ValueError if any top-level key looks like a credential."""
    for key in raw:
        if _CREDENTIAL_PATTERN.match(key):
            valid = list(QuarryConfig.model_fields.keys())
            msg = (
                f"quarry.toml contains a credential-like key '{key}'. "
                f"Never store secrets in quarry.toml. "
                f"Valid top-level keys are: {valid}"
            )
            raise ValueError(msg)


def load_quarry_config(path: Path | None = None) -> QuarryConfig:
    """Load and parse a quarry.toml file.

    Search order:
    1. Explicit *path* argument (if provided and exists).
    2. ``quarry.toml`` in the current working directory.
    3. ``~/.config/quarry/quarry.toml``.
    4. Return all-defaults ``QuarryConfig()`` if none found.

    Raises ``ValueError`` at parse time if the file contains credential-like
    top-level keys (e.g. ``ANTHROPIC_API_KEY``).
    """
    candidates: list[Path] = []
    if path is not None:
        candidates.append(path)
    candidates.append(Path.cwd() / "quarry.toml")
    candidates.append(Path.home() / ".config" / "quarry" / "quarry.toml")

    for candidate in candidates:
        if candidate.exists():
            text = candidate.read_text(encoding="utf-8")
            raw: dict[str, Any] = tomllib.loads(text)
            _check_for_credentials(raw)
            return QuarryConfig.model_validate(raw)

    return QuarryConfig()


def resolve_panel(config: QuarryConfig, panel_name: str | None = None) -> dict[str, RoleConfig]:
    """Merge the named panel over DEFAULT_PANEL role-by-role.

    If *panel_name* is None, or the named panel does not exist in *config*,
    the DEFAULT_PANEL is returned unchanged.
    """
    result = dict(DEFAULT_PANEL)

    if panel_name and panel_name in config.panels:
        named = config.panels[panel_name]
        for role, role_cfg in named.roles.items():
            result[role] = role_cfg

    return result


def resolve_focus(
    cli_focus: list[str] | None,
    config_focus: list[str],
    default: list[VulnerabilityClass] | None = None,
) -> list[VulnerabilityClass]:
    """Resolve the active vulnerability class set for a scan.

    Precedence: CLI flag > TUI selection > config-file default > all classes.

    Raises ``ValueError`` if any token is not a valid ``VulnerabilityClass``
    (listing valid choices in the message), or if the resolved set is empty.
    """
    if default is None:
        default = list(VulnerabilityClass)

    valid_values = {v.value: v for v in VulnerabilityClass}

    def _parse(tokens: list[str]) -> list[VulnerabilityClass]:
        result: list[VulnerabilityClass] = []
        bad: list[str] = []
        for token in tokens:
            if token in valid_values:
                result.append(valid_values[token])
            else:
                bad.append(token)
        if bad:
            valid_list = sorted(valid_values.keys())
            msg = f"Unknown vulnerability class(es): {bad}. Valid choices: {valid_list}"
            raise ValueError(msg)
        return result

    if cli_focus is not None:
        resolved = _parse(cli_focus)
    elif config_focus:
        resolved = _parse(config_focus)
    else:
        resolved = list(default)

    if not resolved:
        valid_list = sorted(valid_values.keys())
        msg = f"The resolved focus set is empty. Valid choices: {valid_list}"
        raise ValueError(msg)

    return resolved


class DynamicValidationConfig:
    """Resolved live-dynamic validation settings for a scan.

    Created by ``resolve_dynamic()`` only when all safety gates pass.
    An instance is truthy; ``None`` means the live path is inactive.
    """

    def __init__(
        self,
        target: Target,
        authorization: TargetAuthorization,
        dynamic_validation_enabled: bool,
        live_prove_enabled: bool,
    ) -> None:
        self.target = target
        self.authorization = authorization
        self.dynamic_validation_enabled = dynamic_validation_enabled
        self.live_prove_enabled = live_prove_enabled


def resolve_dynamic(
    target: Target,
    *,
    dynamic_validation_enabled: bool,
    live_prove_enabled: bool,
    target_authorization: TargetAuthorization | None,
) -> DynamicValidationConfig | None:
    """Validate the live-dynamic path gates and return config or None.

    Returns ``None`` when both live flags are off — the pipeline is unchanged.
    Raises ``ValueError`` with a clear message if a live flag is on but any
    required prerequisite is missing (fail-fast before any model call, consistent
    with ``resolve_focus()``).

    Enforces ADR-017's Layers 1–3:
    - Layer 1: Config gate (flags default False; this function is the check).
    - Layer 2: Target gate (target_url + non-empty allowed_hosts).
    - Layer 3: Authorization ceiling (non-expired TargetAuthorization).
    """
    if not dynamic_validation_enabled and not live_prove_enabled:
        # Both flags off → live path is inert; URL presence does NOT flip this.
        # (ADR-017 "Alternatives considered": "Make live validation always enabled
        # when a target URL is present" was explicitly rejected.)
        return None

    # Layer 2: target_url is required
    if not target.target_url:
        flag = "--dynamic-validation" if dynamic_validation_enabled else "--live-prove"
        msg = (
            f"{flag} requires --target-url to be set. "
            "Provide the base URL of the authorized target."
        )
        raise ValueError(msg)

    # Layer 2: allowed_hosts must not be empty
    if not target.allowed_hosts:
        msg = (
            "Live dynamic validation requires Target.allowed_hosts to be non-empty. "
            "Set allowed_hosts to the host(s) the scanner may contact."
        )
        raise ValueError(msg)

    # Layer 3: a valid, non-expired TargetAuthorization is required
    if target_authorization is None:
        msg = (
            "Live dynamic validation requires a TargetAuthorization. "
            "Create one with: quarry auth create --target-url <url>"
        )
        raise ValueError(msg)

    if target_authorization.expires_at is not None:
        now = datetime.now(UTC)
        if target_authorization.expires_at < now:
            msg = (
                f"TargetAuthorization '{target_authorization.id}' expired at "
                f"{target_authorization.expires_at.isoformat()}. "
                "Create a new authorization to proceed."
            )
            raise ValueError(msg)

    return DynamicValidationConfig(
        target=target,
        authorization=target_authorization,
        dynamic_validation_enabled=dynamic_validation_enabled,
        live_prove_enabled=live_prove_enabled,
    )
