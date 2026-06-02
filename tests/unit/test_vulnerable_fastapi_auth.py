"""Unit tests for auth middleware in vulnerable FastAPI app.

Drives the app through httpx's ASGI transport rather than FastAPI's test client,
which imports the deprecated ``starlette.testclient`` httpx path. ``ASGITransport``
is async-only, so these tests use ``AsyncClient`` (pytest-asyncio auto mode).
"""

from __future__ import annotations

import base64
import importlib.util
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest_asyncio


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """Load the vulnerable FastAPI app and return an httpx client bound to it."""
    app_path = Path("examples/vulnerable-fastapi/app.py")
    spec = importlib.util.spec_from_file_location("vulnerable_fastapi_app", app_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    transport = httpx.ASGITransport(app=module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client


def _make_basic_auth_header(username: str, password: str) -> str:
    """Create a Basic auth header value (without 'Basic ' prefix)."""
    credentials = f"{username}:{password}"
    return base64.b64encode(credentials.encode("utf-8")).decode("utf-8")


async def test_basic_auth_valid_credentials(client: httpx.AsyncClient) -> None:
    """GET /users/1 with valid Basic auth returns 200."""
    auth_value = _make_basic_auth_header("user-a", "pass-a")
    response = await client.get("/users/1", headers={"Authorization": f"Basic {auth_value}"})

    assert response.status_code == 200
    data: dict[str, str] = response.json()
    assert data["id"] == "1"
    assert data["name"] == "Ada"
    assert data["email"] == "ada@example.test"


async def test_basic_auth_invalid_credentials(client: httpx.AsyncClient) -> None:
    """GET /users/1 with invalid Basic auth returns 401."""
    auth_value = _make_basic_auth_header("user-a", "wrong-password")
    response = await client.get("/users/1", headers={"Authorization": f"Basic {auth_value}"})

    assert response.status_code == 401
    data: dict[str, str] = response.json()
    assert data["detail"] == "Invalid credentials"
    assert response.headers.get("WWW-Authenticate") == "Basic"


async def test_public_endpoints_no_auth(client: httpx.AsyncClient) -> None:
    """GET /health and /config work without auth headers."""
    health_response = await client.get("/health")
    assert health_response.status_code == 200
    assert health_response.json() == {"status": "ok"}

    config_response = await client.get("/config")
    assert config_response.status_code == 200
    data: dict[str, str] = config_response.json()
    assert "admin_api_key" in data
    assert data["admin_api_key"] == "demo-admin-key-please-rotate"


async def test_backward_compatibility_no_auth(client: httpx.AsyncClient) -> None:
    """GET /users/1 works without auth headers (returns 200)."""
    response = await client.get("/users/1")

    assert response.status_code == 200
    data: dict[str, str] = response.json()
    assert data["id"] == "1"
    assert data["name"] == "Ada"
    assert data["email"] == "ada@example.test"


async def test_idor_with_auth(client: httpx.AsyncClient) -> None:
    """GET /users/2 with User A credentials returns 200 (proves IDOR)."""
    auth_value = _make_basic_auth_header("user-a", "pass-a")
    response = await client.get("/users/2", headers={"Authorization": f"Basic {auth_value}"})

    assert response.status_code == 200
    data: dict[str, str] = response.json()
    assert data["id"] == "2"
    assert data["name"] == "Grace"
    assert data["email"] == "grace@example.test"
