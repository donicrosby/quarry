"""Tests for Quarry server health endpoint."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from quarry_server.app import create_app


@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient]:
    mock_client = AsyncMock()
    with patch("quarry_server.app.Client.connect", return_value=mock_client):
        app = create_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


async def test_healthz(client: AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
