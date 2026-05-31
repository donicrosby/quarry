from __future__ import annotations

from typing import Any

import httpx


class QuarryClient:
    """Async HTTP client for the Quarry API."""

    def __init__(self, base_url: str = "http://localhost:8000") -> None:
        self.base_url = base_url
        self._client = httpx.AsyncClient(base_url=base_url)

    async def start_scan(self, repo_path: str, target_url: str | None = None) -> dict[str, Any]:
        raise NotImplementedError

    async def get_scan(self, scan_id: str) -> dict[str, Any]:
        raise NotImplementedError

    async def list_scans(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        raise NotImplementedError

    async def cancel_scan(self, scan_id: str) -> dict[str, Any]:
        raise NotImplementedError

    async def get_findings(self, scan_id: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def get_attack_surface(self, scan_id: str) -> list[dict[str, Any]]:
        raise NotImplementedError
