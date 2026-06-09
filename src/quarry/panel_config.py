"""quarry.toml configuration loader and panel/focus resolver.

Reads the TOML-based multi-model panel configuration, merges named panels over
the built-in DEFAULT_PANEL role-by-role, and resolves the active vulnerability
class focus for a scan.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from quarry.schemas import Provider, VulnerabilityClass


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
    "recon": RoleConfig(provider="mock", model="mock-v1", rpm=30),
    "hunt": RoleConfig(provider="mock", model="mock-v1", rpm=30),
    "validate": RoleConfig(provider="mock", model="mock-v1", rpm=30),
    "gapfill": RoleConfig(provider="mock", model="mock-v1", rpm=30),
    "prove": RoleConfig(provider="mock", model="mock-v1", rpm=30),
    "trace": RoleConfig(provider="mock", model="mock-v1", rpm=30),
    "report": RoleConfig(provider="mock", model="mock-v1", rpm=30),
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


class QuarryConfig(BaseModel):
    """Top-level parsed quarry.toml configuration."""

    panels: dict[str, NamedPanel] = Field(default_factory=dict)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    scan_defaults: ScanDefaultsConfig = Field(default_factory=ScanDefaultsConfig)


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
