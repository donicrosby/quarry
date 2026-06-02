"""Unit tests for auth middleware in vulnerable FastAPI app."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> TestClient:
    """Load the vulnerable FastAPI app and return a TestClient."""
    import importlib.util

    app_path = Path("examples/vulnerable-fastapi/app.py")
    spec = importlib.util.spec_from_file_location("vulnerable_fastapi_app", app_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return TestClient(module.app)


def _make_basic_auth_header(username: str, password: str) -> str:
    """Create a Basic auth header value (without 'Basic ' prefix)."""
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    return encoded


def test_basic_auth_valid_credentials(client: TestClient) -> None:
    """GET /users/1 with valid Basic auth returns 200."""
    auth_value = _make_basic_auth_header("user-a", "pass-a")
    response = client.get("/users/1", headers={"Authorization": f"Basic {auth_value}"})  # type: ignore[unknown]

    assert response.status_code == 200
    data: dict[str, str] = response.json()  # type: ignore[unknown]
    assert data["id"] == "1"
    assert data["name"] == "Ada"
    assert data["email"] == "ada@example.test"


def test_basic_auth_invalid_credentials(client: TestClient) -> None:
    """GET /users/1 with invalid Basic auth returns 401."""
    auth_value = _make_basic_auth_header("user-a", "wrong-password")
    response = client.get("/users/1", headers={"Authorization": f"Basic {auth_value}"})  # type: ignore[unknown]

    assert response.status_code == 401
    data: dict[str, str] = response.json()  # type: ignore[unknown]
    assert data["detail"] == "Invalid credentials"
    assert response.headers.get("WWW-Authenticate") == "Basic"


def test_public_endpoints_no_auth(client: TestClient) -> None:
    """GET /health and /config work without auth headers."""
    # Test /health endpoint
    health_response = client.get("/health")  # type: ignore[unknown]
    assert health_response.status_code == 200
    assert health_response.json() == {"status": "ok"}  # type: ignore[unknown]

    # Test /config endpoint
    config_response = client.get("/config")  # type: ignore[unknown]
    assert config_response.status_code == 200
    data: dict[str, str] = config_response.json()  # type: ignore[unknown]
    assert "admin_api_key" in data
    assert data["admin_api_key"] == "demo-admin-key-please-rotate"


def test_backward_compatibility_no_auth(client: TestClient) -> None:
    """GET /users/1 works without auth headers (returns 200)."""
    response = client.get("/users/1")  # type: ignore[unknown]

    assert response.status_code == 200
    data: dict[str, str] = response.json()  # type: ignore[unknown]
    assert data["id"] == "1"
    assert data["name"] == "Ada"
    assert data["email"] == "ada@example.test"


def test_idor_with_auth(client: TestClient) -> None:
    """GET /users/2 with User A credentials returns 200 (proves IDOR)."""
    auth_value = _make_basic_auth_header("user-a", "pass-a")
    response = client.get("/users/2", headers={"Authorization": f"Basic {auth_value}"})  # type: ignore[unknown]

    assert response.status_code == 200
    data: dict[str, str] = response.json()  # type: ignore[unknown]
    assert data["id"] == "2"
    assert data["name"] == "Grace"
    assert data["email"] == "grace@example.test"
