"""Tests for the IntegrationConfig schema."""

from __future__ import annotations

import pytest


def test_integration_config_round_trips() -> None:
    from quarry.schemas import IntegrationConfig, SecretRef, Severity

    config = IntegrationConfig(
        integration_type="slack_notify",
        enabled=True,
        dry_run=False,
        config={"channel": "#alerts"},
        secret_ref=SecretRef(env="QUARRY_SECRET_SLACK_WEBHOOK"),
        severity_threshold=Severity.CRITICAL,
    )
    restored = IntegrationConfig.model_validate(config.model_dump(mode="json"))
    assert restored == config


def test_integration_config_defaults() -> None:
    from quarry.schemas import IntegrationConfig, Severity

    config = IntegrationConfig(integration_type="slack_notify")
    assert config.enabled is False
    assert config.dry_run is True
    assert config.secret_ref is None
    assert config.severity_threshold == Severity.CRITICAL
    assert config.config == {}


def test_integration_config_rejects_inline_looking_secret() -> None:
    from quarry.schemas import IntegrationConfig, SecretRef

    with pytest.raises(ValueError, match="inline credential"):
        IntegrationConfig(
            integration_type="slack_notify",
            secret_ref=SecretRef(env="sk-abcdefghijklmnop"),
        )


def test_scan_profile_integration_configs_defaults_empty() -> None:
    from quarry.schemas import ScanProfile, VulnerabilityClass

    profile = ScanProfile(
        id="p-1",
        name="test",
        vuln_classes=[VulnerabilityClass.SECRETS],
    )
    assert profile.integration_configs == []
