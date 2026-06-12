"""Tests for ToolRunner host-allowlist guard (ADR-017, safety Layer 5.5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from quarry_models.types import BudgetSpec
from quarry_tools.runner import ToolCallRecord, ToolRunner
from quarry_tools.spec import ToolRegistry


def _http_registry() -> ToolRegistry:
    class HttpRequestTool:
        name = "http_request"
        description = "Live HTTP tool"
        input_schema: dict[str, Any] = {"type": "object"}
        roles = ["dynamic_validate", "prove"]

        def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
            return '{"dispatch": "pending"}'

    return {"http_request": HttpRequestTool()}  # type: ignore[dict-item]


def _make_runner(tmp_path: Path, allowed_hosts: list[str] | None = None) -> ToolRunner:
    budget = BudgetSpec(max_cost_usd=10.0)
    return ToolRunner(
        repo_root=tmp_path,
        role="dynamic_validate",
        registry=_http_registry(),
        budget_spec=budget,
        allowed_hosts=allowed_hosts,
    )


def test_empty_allowed_hosts_blocks_http_request(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, allowed_hosts=[])
    record = runner.run("http_request", {"method": "GET", "path": "/users/1"})
    assert record.allowed is False
    assert record.status == "refused"
    assert record.denied_reason is not None


def test_empty_allowed_hosts_refused_record_is_never_dropped(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, allowed_hosts=[])
    record = runner.run("http_request", {"method": "POST", "path": "/anything"})
    assert isinstance(record, ToolCallRecord)
    assert record.allowed is False


def test_host_not_in_allowed_hosts_is_refused(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, allowed_hosts=["localhost"])
    record = runner.run("http_request", {"method": "GET", "path": "/users/1", "host": "evil.com"})
    assert record.allowed is False
    assert record.status == "refused"
    assert record.denied_reason is not None


def test_refused_denied_reason_references_blocked_host(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, allowed_hosts=["localhost"])
    record = runner.run("http_request", {"method": "GET", "path": "/steal", "host": "attacker.io"})
    assert record.denied_reason is not None
    assert "attacker.io" in record.denied_reason or "allowed" in record.denied_reason.lower()


def test_host_in_allowed_hosts_is_allowed(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, allowed_hosts=["localhost"])
    record = runner.run("http_request", {"method": "GET", "path": "/users/1", "host": "localhost"})
    assert record.allowed is True


def test_multiple_allowed_hosts_any_match_passes(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, allowed_hosts=["localhost", "staging.internal"])
    record = runner.run(
        "http_request",
        {"method": "GET", "path": "/api/v1", "host": "staging.internal"},
    )
    assert record.allowed is True


def test_no_host_in_inputs_with_non_empty_allowed_hosts_is_allowed(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, allowed_hosts=["localhost"])
    record = runner.run("http_request", {"method": "GET", "path": "/users/1"})
    assert record.allowed is True


def test_guard_does_not_affect_non_http_tools(tmp_path: Path) -> None:
    from quarry_tools.builtins import BUILTIN_REGISTRY

    budget = BudgetSpec(max_cost_usd=10.0)
    runner = ToolRunner(
        repo_root=tmp_path,
        role="hunt",
        registry=BUILTIN_REGISTRY,
        budget_spec=budget,
        allowed_hosts=[],
    )
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello")
    record = runner.run("read_file", {"path": "test.txt"})
    assert record.allowed is True


def test_none_allowed_hosts_does_not_block_http_request(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, allowed_hosts=None)
    record = runner.run("http_request", {"method": "GET", "path": "/users/1"})
    assert record.allowed is True
