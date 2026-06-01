from __future__ import annotations

import json
from types import TracebackType
from typing import Any, Self, cast

import httpx

from quarry.schemas import AttackSurfaceItem, CandidateFinding, FinalFinding, Scan, ScanSummary

FindingsResponse = dict[str, list[CandidateFinding] | list[FinalFinding]]


class QuarryClient:
    """Async HTTP client for the Quarry API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout, transport=transport)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def start_scan(self, repo_path: str, target_url: str | None = None) -> dict[str, str]:
        response = await self._client.post(
            "/scans",
            json={"repo_path": repo_path, "target_url": target_url},
        )
        response.raise_for_status()
        payload = _json_object(response)
        return {"scan_id": str(payload["scan_id"]), "status": str(payload["status"])}

    async def start_diff_scan(
        self,
        repo_path: str,
        base_commit: str,
        head_commit: str,
    ) -> dict[str, str]:
        response = await self._client.post(
            "/scans/diff",
            json={
                "repo_path": repo_path,
                "base_commit": base_commit,
                "head_commit": head_commit,
            },
        )
        response.raise_for_status()
        payload = _json_object(response)
        return {"scan_id": str(payload["scan_id"]), "status": str(payload["status"])}

    async def get_scan(self, scan_id: str) -> Scan:
        response = await self._client.get(f"/scans/{scan_id}")
        response.raise_for_status()
        return Scan.model_validate(_json_object(response))

    async def list_scans(self) -> list[ScanSummary]:
        response = await self._client.get("/scans")
        response.raise_for_status()
        return [ScanSummary.model_validate(item) for item in _json_list(response)]

    async def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        async with self._client.stream("GET", f"/scans/{scan_id}/status") as response:
            response.raise_for_status()
            data_lines: list[str] = []
            async for line in response.aiter_lines():
                if line == "":
                    parsed = _parse_sse_data(data_lines)
                    if parsed is not None:
                        return parsed
                    data_lines.clear()
                    continue
                if line.startswith("data:"):
                    data_lines.append(line.removeprefix("data:").strip())

            parsed = _parse_sse_data(data_lines)
            if parsed is not None:
                return parsed
        return {}

    async def cancel_scan(self, scan_id: str) -> dict[str, str]:
        response = await self._client.post(f"/scans/{scan_id}/cancel")
        response.raise_for_status()
        payload = _json_object(response)
        return {"scan_id": str(payload["scan_id"]), "status": str(payload["status"])}

    async def resume_scan(self, scan_id: str) -> dict[str, str]:
        response = await self._client.post(f"/scans/{scan_id}/resume")
        response.raise_for_status()
        payload = _json_object(response)
        return {"scan_id": str(payload["scan_id"]), "status": str(payload["status"])}

    async def get_findings(self, scan_id: str) -> FindingsResponse:
        response = await self._client.get(f"/scans/{scan_id}/findings")
        response.raise_for_status()
        payload = _json_object(response)
        candidate_findings = _required_json_list(payload, "candidate_findings")
        final_findings = _required_json_list(payload, "final_findings")
        return {
            "candidate_findings": [
                CandidateFinding.model_validate(item) for item in candidate_findings
            ],
            "final_findings": [FinalFinding.model_validate(item) for item in final_findings],
        }

    async def get_attack_surface(self, scan_id: str) -> list[AttackSurfaceItem]:
        response = await self._client.get(f"/scans/{scan_id}/attack-surface")
        response.raise_for_status()
        return [AttackSurfaceItem.model_validate(item) for item in _json_list(response)]


def _json_object(response: httpx.Response) -> dict[str, Any]:
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("Expected JSON object response")
    return cast(dict[str, Any], payload)


def _json_list(response: httpx.Response) -> list[Any]:
    payload = response.json()
    if not isinstance(payload, list):
        raise ValueError("Expected JSON array response")
    return cast(list[Any], payload)


def _required_json_list(payload: dict[str, Any], key: str) -> list[Any]:
    value = payload[key]
    if not isinstance(value, list):
        raise ValueError(f"Expected '{key}' to be a JSON array")
    return cast(list[Any], value)


def _parse_sse_data(data_lines: list[str]) -> dict[str, Any] | None:
    if not data_lines:
        return None
    payload = json.loads("\n".join(data_lines))
    if not isinstance(payload, dict):
        return {"data": payload}
    return cast(dict[str, Any], payload)
