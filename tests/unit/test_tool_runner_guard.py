"""Tests for the ToolRunner scope-exclusion hard-guard (ADR-017, safety Layer 4).

Written RED first — these fail until ToolRunner._check_scope_exclusion is
implemented and ToolRunner accepts a scope_exclusions parameter.

Key invariants:
- A scope-excluded http_request produces a refused ToolCallRecord
  (allowed=False, denied_reason contains the exclusion value, status="refused").
- Refusal is NEVER silent — the record is always returned, never dropped.
- Matching covers kind in: route, functional_area, path_glob, vuln_class.
- A path_glob exclusion (e.g. "src/billing/**") also blocks requests whose
  resolved URL contains the mapped path prefix (e.g. "/billing/").
- Five of six safety layers satisfied still results in refusal if layer 4 fires.
- When no exclusion matches, the tool runs normally.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from quarry.schemas import ScopeExclusion
from quarry_tools.runner import ToolCallRecord, ToolRunner
from quarry_tools.spec import ToolRegistry

# ---------------------------------------------------------------------------
# Minimal http_request stub (so tests don't need a network or real tool)
# ---------------------------------------------------------------------------


def _http_registry() -> ToolRegistry:
    class HttpRequestTool:
        name = "http_request"
        description = "Live HTTP tool"
        input_schema: dict[str, Any] = {"type": "object"}
        roles = ["dynamic_validate", "prove"]

        def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
            return '{"dispatch": "pending"}'

    return {"http_request": HttpRequestTool()}  # type: ignore[dict-item]


def _make_runner(
    tmp_path: Path,
    role: str = "dynamic_validate",
    scope_exclusions: list[ScopeExclusion] | None = None,
) -> ToolRunner:
    return ToolRunner(
        repo_root=tmp_path,
        role=role,
        registry=_http_registry(),
        scope_exclusions=scope_exclusions or [],
    )


# ---------------------------------------------------------------------------
# No-exclusion baseline — tool runs normally
# ---------------------------------------------------------------------------


def test_no_exclusions_allows_request(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path)
    record = runner.run("http_request", {"method": "GET", "path": "/users/1"})
    assert record.allowed is True
    assert record.denied_reason is None


# ---------------------------------------------------------------------------
# Route exclusion (kind="route")
# ---------------------------------------------------------------------------


def test_route_exclusion_refuses_matching_request(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="route",
            value="GET /admin/*",
            reason="Admin endpoints off-limits",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("http_request", {"method": "GET", "path": "/admin/users"})
    assert record.allowed is False
    assert record.denied_reason is not None
    assert "GET /admin/*" in record.denied_reason or "route" in record.denied_reason
    assert record.status == "refused"


def test_route_exclusion_without_block_dynamic_does_not_refuse(tmp_path: Path) -> None:
    """An exclusion with block_dynamic=False must not block live HTTP."""
    exclusions = [
        ScopeExclusion(
            kind="route",
            value="GET /admin/*",
            reason="Static only",
            block_dynamic=False,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("http_request", {"method": "GET", "path": "/admin/users"})
    assert record.allowed is True


def test_non_matching_route_allows_request(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="route",
            value="GET /billing/*",
            reason="Billing off-limits",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("http_request", {"method": "GET", "path": "/users/1"})
    assert record.allowed is True


# ---------------------------------------------------------------------------
# Functional area exclusion (kind="functional_area")
# ---------------------------------------------------------------------------


def test_functional_area_exclusion_refuses_request(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="functional_area",
            value="billing",
            reason="Billing out of scope",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run(
        "http_request",
        {"method": "POST", "path": "/billing/charge", "functional_area": "billing"},
    )
    assert record.allowed is False
    assert record.status == "refused"


# ---------------------------------------------------------------------------
# Path glob exclusion (kind="path_glob") — maps to URL prefix
# ---------------------------------------------------------------------------


def test_path_glob_exclusion_blocks_url_with_matching_prefix(tmp_path: Path) -> None:
    """src/billing/** must block requests to /billing/ paths."""
    exclusions = [
        ScopeExclusion(
            kind="path_glob",
            value="src/billing/**",
            reason="Billing module excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("http_request", {"method": "GET", "path": "/billing/invoices"})
    assert record.allowed is False
    assert record.status == "refused"


def test_path_glob_exclusion_allows_non_matching_url(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="path_glob",
            value="src/billing/**",
            reason="Billing module excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("http_request", {"method": "GET", "path": "/users/profile"})
    assert record.allowed is True


# ---------------------------------------------------------------------------
# Vuln-class exclusion (kind="vuln_class")
# ---------------------------------------------------------------------------


def test_vuln_class_exclusion_refuses_matching_request(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="vuln_class",
            value="idor",
            reason="IDOR testing authorized separately",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run(
        "http_request",
        {"method": "GET", "path": "/users/2", "vuln_class": "idor"},
    )
    assert record.allowed is False
    assert record.status == "refused"


# ---------------------------------------------------------------------------
# Refusal record shape
# ---------------------------------------------------------------------------


def test_refused_record_has_denied_reason(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="route",
            value="DELETE /resources/*",
            reason="Destructive ops excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("http_request", {"method": "DELETE", "path": "/resources/42"})
    assert record.allowed is False
    assert isinstance(record.denied_reason, str) and record.denied_reason
    assert record.status == "refused"


def test_refused_record_is_never_silently_dropped(tmp_path: Path) -> None:
    """The guard must ALWAYS return a ToolCallRecord — never raise or swallow."""
    exclusions = [
        ScopeExclusion(
            kind="route",
            value="*",
            reason="All routes blocked",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    # Must return a record, not raise
    record = runner.run("http_request", {"method": "GET", "path": "/anything"})
    assert isinstance(record, ToolCallRecord)
    assert record.allowed is False


# ---------------------------------------------------------------------------
# Guard only applies to http_request, not to static tools
# ---------------------------------------------------------------------------


def test_scope_exclusion_does_not_affect_non_dynamic_tool(tmp_path: Path) -> None:
    """Static tools like read_file are unaffected by scope_exclusions."""
    from quarry_tools.builtins import BUILTIN_REGISTRY

    exclusions = [
        ScopeExclusion(
            kind="path_glob",
            value="src/billing/**",
            reason="Billing excluded",
            block_dynamic=True,
        )
    ]
    runner = ToolRunner(
        repo_root=tmp_path,
        role="hunt",
        registry=BUILTIN_REGISTRY,
        scope_exclusions=exclusions,
    )
    # read_file is not an http_request — the guard should not block it
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello")
    record = runner.run("read_file", {"path": "test.txt"})
    assert record.allowed is True
