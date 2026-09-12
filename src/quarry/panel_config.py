"""quarry.toml configuration loader and panel/focus resolver.

Reads the TOML-based multi-model panel configuration, merges named panels over
the built-in DEFAULT_PANEL role-by-role, and resolves the active vulnerability
class focus for a scan.
"""

from __future__ import annotations

import os
import re
import tomllib
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from quarry.schemas import (
    AuthProfile,
    AuthProfileKind,
    AuthProfileSet,
    IntegrationConfig,
    Provider,
    Severity,
    Target,
    TargetAuthorization,
    VulnerabilityClass,
    parse_secret_ref_template,
)


def _empty_vuln_classes() -> list[VulnerabilityClass]:
    return []


# Upper bound for the exploratory-injection fraction (cpc slice 6). A gapfill
# pass is always majority threat-model-driven; the exploratory hedge is capped
# at half the pass by construction (gapfill.exploratory_injection_count clamps
# independently, so a bad value degrades gracefully rather than corrupting the
# scan shape).
EXPLORATORY_INJECTION_MAX_FRACTION = 0.5


# Keys matching this pattern in the raw TOML top level are rejected at parse
# time to prevent secrets from leaking into config files.
_CREDENTIAL_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD|_CREDENTIAL)$")


class TierKind(StrEnum):
    """The function a model tier serves within a role (MDASH ensemble, design D1).

    ``reasoner`` is the SOTA heavy-reasoning pass, ``debater`` the cheaper distilled
    model that argues to refute on high-volume passes, and ``counterpoint`` a second
    independent SOTA model. A single-model role is an implicit one-entry reasoner tier.
    """

    REASONER = "reasoner"
    DEBATER = "debater"
    COUNTERPOINT = "counterpoint"


class ModelTier(BaseModel):
    """One tier within a role: a model with its own provider, regime, and caps."""

    kind: TierKind = TierKind.REASONER
    provider: Provider = Provider.MOCK
    model: str = ""
    rpm: int = 30
    turn_timeout_seconds: int = 120
    # Prompt regime name (e.g. "refute" for a debater) — lets a tier run a distinct
    # prompt from the model that produced the candidate (ADR-021 independence, D2).
    prompt_regime: str = ""
    # Per-role caps the reference panel specifies (currently-absent knobs).
    tool_call_cap: int | None = None
    thinking_budget_tokens: int | None = None


def _empty_tiers() -> list[ModelTier]:
    return []


class RoleConfig(BaseModel):
    """Configuration for one model role in a panel.

    A role is single-model by default (``provider``/``model``). It MAY instead declare
    an ordered ``tiers`` set (reasoner / debater / counterpoint) — see design D1. A
    single-model role is equivalent to a one-entry reasoner tier, so existing configs
    keep working unchanged.
    """

    provider: Provider = Provider.MOCK
    model: str = ""
    rpm: int = 30
    # Per-turn model-call timeout. Chutes open-weight models can queue for
    # minutes; 120 s is a fail-fast default that surfaces hangs quickly so the
    # activity retries rather than blocking the entire scan.
    turn_timeout_seconds: int = 120
    # Per-role caps (also settable per tier). Unset = bounded only by global caps.
    tool_call_cap: int | None = None
    thinking_budget_tokens: int | None = None
    # Optional ordered tier set. Empty = single-model role (implicit reasoner tier).
    tiers: list[ModelTier] = Field(default_factory=_empty_tiers)


def resolve_tier(role: RoleConfig, kind: TierKind) -> ModelTier | None:
    """Return the ``ModelTier`` serving *kind* for *role*, or ``None`` if unconfigured.

    A tiered role returns its matching tier entry. A single-model role has an implicit
    reasoner tier synthesised from its top-level fields (backward compatible) and no
    debater / counterpoint tier.
    """
    if role.tiers:
        return next((t for t in role.tiers if t.kind == kind), None)
    if kind is TierKind.REASONER:
        return ModelTier(
            kind=TierKind.REASONER,
            provider=role.provider,
            model=role.model,
            rpm=role.rpm,
            turn_timeout_seconds=role.turn_timeout_seconds,
            tool_call_cap=role.tool_call_cap,
            thinking_budget_tokens=role.thinking_budget_tokens,
        )
    return None


def enforce_vendor_allowlist(panel: dict[str, RoleConfig], allowlist: list[str]) -> None:
    """Fail fast if any panel model's vendor is outside *allowlist* (design D6).

    Checks every role — its top-level provider and each of its ``tiers`` — before
    any model call. An empty *allowlist* imposes no restriction (backward
    compatible). Raises ``ValueError`` naming the offending vendor and role so the
    scan fails up front rather than mid-run, consistent with ``resolve_focus`` /
    ``resolve_dynamic``.
    """
    if not allowlist:
        return
    allowed = set(allowlist)
    for role, cfg in panel.items():
        vendors = [t.provider.value for t in cfg.tiers] if cfg.tiers else [cfg.provider.value]
        for vendor in vendors:
            if vendor not in allowed:
                msg = (
                    f"Role '{role}' uses vendor '{vendor}', which is not in the "
                    f"vendor_allowlist {sorted(allowed)}. Add it to the allowlist or "
                    "change the panel before starting the scan."
                )
                raise ValueError(msg)


# The default built-in panel.  All roles fall back here if not overridden.
DEFAULT_PANEL: dict[str, RoleConfig] = {
    "recon": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "hunt": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "validate": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    # calibrate: post-validation severity calibration (severity-calibration
    # capability). Separate from validate to keep the adversarial-review
    # boundary intact — calibration never judges validity, only severity.
    "calibrate": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "gapfill": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "prove": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "trace": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "report": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    # dynamic_validate: live corroboration role (ADR-017). Separate from static
    # validate to keep the network-free adversarial-review boundary intact.
    "dynamic_validate": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    # live_recon / exploit: app-centric live-exploitation track (Shannon pillar).
    # live_recon builds a live attack map; exploit chains stateful exploitation.
    "live_recon": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    "exploit": RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
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
    # Cap on iterative-coverage-loop rounds (ADR-022). Each round re-runs
    # hunt -> validate -> (prove) -> trace; the loop halts sooner on
    # convergence (no new tasks) or budget exhaustion. Default 3 per ADR-022.
    max_coverage_rounds: int = 3
    # Rising-bar early-stop: a round must add at least
    # ``max(1, ceil(f * cumulative_findings))`` new distinct findings to justify
    # another round, so the bar climbs as the scan accumulates findings. Trades
    # recall for cost by design — lower it for a more patient (higher-recall)
    # scan, and set it to 0.0 to disable the rule entirely (exhaustive audit),
    # leaving only convergence / round-cap / budget as stop criteria.
    coverage_yield_threshold: float = Field(default=0.15, ge=0.0, le=1.0)
    # Unconstrained exploratory-investigation injection (cpc slice 6): the
    # fraction of each gapfill pass deliberately spent on open-ended
    # "explore this area" investigations that carry no threat-model-derived
    # context, hedging against tunnel vision. Bounded to the 25–50% band by
    # default; 0.0 disables the injection entirely (gapfill emits only
    # threat-model-driven re-hunt tasks, the pre-guarantee behaviour).
    exploratory_injection_fraction: float = Field(
        default=0.3, ge=0.0, le=EXPLORATORY_INJECTION_MAX_FRACTION
    )
    # Optional fixed seed. When None, each scan derives a deterministic seed
    # from its scan_id UUID so runs are reproducible without pinning a global value.
    seed: int | None = None
    # Names of context-injector (and future non-tool/sink/hook) plugins active
    # for scans using this profile. Empty by default — plugins are disabled
    # unless explicitly named here, per the disabled-by-default invariant.
    plugins_active: list[str] = Field(default_factory=list)
    # Allowed model vendors for the panel (design D6). Empty = unrestricted.
    # When set, every panel role's vendor is validated at scan start via
    # ``enforce_vendor_allowlist`` — a fail-fast before any model call.
    vendor_allowlist: list[str] = Field(default_factory=list)


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


class IntegrationTomlEntry(BaseModel):
    """One ``[integrations.<name>]`` table in quarry.toml.

    ``secret``, if set, MUST be a ``${secret:ENV_VAR_NAME}`` template string —
    never a literal value (see ``resolve_integration_configs``).
    """

    enabled: bool = False
    dry_run: bool = True
    severity_threshold: Severity = Severity.CRITICAL
    secret: str | None = None


class QuarryConfig(BaseModel):
    """Top-level parsed quarry.toml configuration."""

    panels: dict[str, NamedPanel] = Field(default_factory=dict)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    scan_defaults: ScanDefaultsConfig = Field(default_factory=ScanDefaultsConfig)
    retry: RetryConfig = Field(default_factory=RetryConfig)
    integrations: dict[str, IntegrationTomlEntry] = Field(default_factory=dict)
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


def resolve_integration_configs(config: QuarryConfig) -> list[IntegrationConfig]:
    """Build IntegrationConfig entries from quarry.toml [integrations.<name>] tables.

    Raises ValueError if any entry's ``secret`` field is not a
    ``${secret:ENV_VAR_NAME}`` template — literal secret values are never
    accepted, in config files (see ADR on the unified plugin subsystem).
    """
    resolved: list[IntegrationConfig] = []
    for name, entry in config.integrations.items():
        secret_ref = parse_secret_ref_template(entry.secret) if entry.secret is not None else None
        resolved.append(
            IntegrationConfig(
                integration_type=name,
                enabled=entry.enabled,
                dry_run=entry.dry_run,
                severity_threshold=entry.severity_threshold,
                secret_ref=secret_ref,
            )
        )
    return resolved


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


def _assert_env_var_exists(env_name: str) -> None:
    if not os.environ.get(env_name):
        msg = (
            f"Required environment variable '{env_name}' is not set. "
            "Set it in the worker environment before running a scan "
            "with authenticated dynamic validation."
        )
        raise OSError(msg)


def _assert_login_host_in_allowlist(profile: AuthProfile, target: Target) -> None:
    if not target.target_url:
        msg = (
            f"Login-flow profile '{profile.name}' requires a target URL to determine "
            "the login host. Set target.target_url before loading auth profiles."
        )
        raise ValueError(msg)
    parsed = urlparse(target.target_url)
    login_host = parsed.hostname or ""
    if login_host not in target.allowed_hosts:
        msg = (
            f"Login-flow profile '{profile.name}' would POST to host '{login_host}', "
            f"which is not in Target.allowed_hosts {target.allowed_hosts!r}. "
            "Add the host to allowed_hosts before loading this auth profile."
        )
        raise ValueError(msg)


def resolve_auth(config: str | Path, target: Target) -> AuthProfileSet:
    path = Path(config)
    text = path.read_text(encoding="utf-8")
    raw: dict[str, object] = tomllib.loads(text)
    profile_set = AuthProfileSet.model_validate(raw)
    _secret_re = r"\$\{secret:([A-Z0-9_]+)\}"
    for profile in profile_set.profiles:
        if profile.secret_ref is not None:
            _assert_env_var_exists(profile.secret_ref.env)
        if profile.totp is not None:
            _assert_env_var_exists(profile.totp.seed_ref.env)
        if profile.login is not None:
            for val in profile.login.field_template.values():
                for match in re.finditer(_secret_re, val):
                    _assert_env_var_exists(match.group(1))
        if profile.kind == AuthProfileKind.LOGIN_FLOW:
            _assert_login_host_in_allowlist(profile, target)
    return profile_set
