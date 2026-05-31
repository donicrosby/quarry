"""Tests for QuarrySettings configuration."""

import os
from unittest import mock

import pytest
from pydantic import ValidationError


def test_config_defaults() -> None:
    """Test that QuarrySettings uses correct default values."""
    from quarry.config import QuarrySettings

    settings = QuarrySettings()

    assert settings.server_url == "http://localhost:8000"
    assert settings.temporal_address == "localhost:7233"
    assert settings.task_queue == "quarry-control"
    assert settings.server_host == "127.0.0.1"
    assert settings.server_port == 8000
    assert settings.db_path == ".quarry/quarry.db"


def test_config_env_var_override() -> None:
    """Test that environment variables override defaults."""
    from quarry.config import QuarrySettings

    with mock.patch.dict(
        os.environ,
        {
            "QUARRY_TEMPORAL_ADDRESS": "remote-temporal:7233",
            "QUARRY_SERVER_URL": "https://api.example.com",
            "QUARRY_TASK_QUEUE": "custom-queue",
        },
    ):
        settings = QuarrySettings()

        assert settings.temporal_address == "remote-temporal:7233"
        assert settings.server_url == "https://api.example.com"
        assert settings.task_queue == "custom-queue"
        # Unset env vars should use defaults
        assert settings.server_host == "127.0.0.1"
        assert settings.server_port == 8000


def test_config_type_validation_port() -> None:
    """Test that server_port validates as integer."""
    from quarry.config import QuarrySettings

    # Valid integer
    settings = QuarrySettings(server_port=9000)
    assert settings.server_port == 9000

    # String that can be coerced should work
    settings = QuarrySettings(server_port="8080")  # type: ignore[arg-type]
    assert settings.server_port == 8080


def test_config_type_validation_port_failure() -> None:
    """Test that invalid port type raises validation error."""
    from quarry.config import QuarrySettings

    with pytest.raises(ValidationError):
        QuarrySettings(server_port="not-a-number")  # type: ignore[arg-type]


def test_config_all_fields_present() -> None:
    """Test initialization with all fields explicitly set."""
    from quarry.config import QuarrySettings

    settings = QuarrySettings(
        server_url="https://custom-server.com:8443",
        temporal_address="temporal.local:7233",
        task_queue="production-queue",
        server_host="0.0.0.0",
        server_port=9000,
        db_path="/var/lib/quarry/db.sqlite",
    )

    assert settings.server_url == "https://custom-server.com:8443"
    assert settings.temporal_address == "temporal.local:7233"
    assert settings.task_queue == "production-queue"
    assert settings.server_host == "0.0.0.0"
    assert settings.server_port == 9000
    assert settings.db_path == "/var/lib/quarry/db.sqlite"
