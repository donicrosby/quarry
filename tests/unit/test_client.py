from __future__ import annotations

import inspect

import pytest

from quarry_client.client import QuarryClient


class TestQuarryClientConstruction:
    def test_default_base_url(self) -> None:
        client = QuarryClient()
        assert client.base_url == "http://localhost:8000"

    def test_custom_base_url(self) -> None:
        client = QuarryClient(base_url="http://example.com:9999")
        assert client.base_url == "http://example.com:9999"

    def test_client_stores_httpx_async_client(self) -> None:
        client = QuarryClient(base_url="http://test:9999")
        assert client.base_url == "http://test:9999"


EXPECTED_METHODS = [
    "start_scan",
    "get_scan",
    "list_scans",
    "get_scan_status",
    "cancel_scan",
    "get_findings",
    "get_attack_surface",
]


class TestQuarryClientMethods:
    @pytest.mark.parametrize("method_name", EXPECTED_METHODS)
    def test_method_exists(self, method_name: str) -> None:
        client = QuarryClient()
        assert hasattr(client, method_name)
        assert callable(getattr(client, method_name))

    @pytest.mark.parametrize("method_name", EXPECTED_METHODS)
    def test_method_is_async(self, method_name: str) -> None:
        method = getattr(QuarryClient, method_name)
        assert inspect.iscoroutinefunction(method)


class TestQuarryClientMethodSignatures:
    def test_start_scan_signature(self) -> None:
        sig = inspect.signature(QuarryClient.start_scan)
        params = list(sig.parameters.keys())
        assert params == ["self", "repo_path", "target_url"]
        assert sig.parameters["repo_path"].annotation == "str"
        assert sig.parameters["target_url"].annotation == "str | None"
        assert sig.return_annotation == "dict[str, Any]"

    def test_get_scan_signature(self) -> None:
        sig = inspect.signature(QuarryClient.get_scan)
        params = list(sig.parameters.keys())
        assert params == ["self", "scan_id"]
        assert sig.parameters["scan_id"].annotation == "str"
        assert sig.return_annotation == "dict[str, Any]"

    def test_list_scans_signature(self) -> None:
        sig = inspect.signature(QuarryClient.list_scans)
        params = list(sig.parameters.keys())
        assert params == ["self"]
        assert sig.return_annotation == "list[dict[str, Any]]"

    def test_get_scan_status_signature(self) -> None:
        sig = inspect.signature(QuarryClient.get_scan_status)
        params = list(sig.parameters.keys())
        assert params == ["self", "scan_id"]
        assert sig.parameters["scan_id"].annotation == "str"
        assert sig.return_annotation == "dict[str, Any]"

    def test_cancel_scan_signature(self) -> None:
        sig = inspect.signature(QuarryClient.cancel_scan)
        params = list(sig.parameters.keys())
        assert params == ["self", "scan_id"]
        assert sig.parameters["scan_id"].annotation == "str"
        assert sig.return_annotation == "dict[str, Any]"

    def test_get_findings_signature(self) -> None:
        sig = inspect.signature(QuarryClient.get_findings)
        params = list(sig.parameters.keys())
        assert params == ["self", "scan_id"]
        assert sig.parameters["scan_id"].annotation == "str"
        assert sig.return_annotation == "list[dict[str, Any]]"

    def test_get_attack_surface_signature(self) -> None:
        sig = inspect.signature(QuarryClient.get_attack_surface)
        params = list(sig.parameters.keys())
        assert params == ["self", "scan_id"]
        assert sig.parameters["scan_id"].annotation == "str"
        assert sig.return_annotation == "list[dict[str, Any]]"
