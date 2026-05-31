from pathlib import Path

import pytest

from quarry_activities.target import validate_local_host


def test_validate_local_host_accepts_loopback_names() -> None:
    validate_local_host("127.0.0.1")
    validate_local_host("localhost")


def test_validate_local_host_rejects_non_local_target() -> None:
    with pytest.raises(ValueError, match="Only localhost targets are allowed"):
        validate_local_host("example.com")


def test_vulnerable_target_app_file_exists() -> None:
    assert Path("examples/vulnerable-fastapi/app.py").exists()
