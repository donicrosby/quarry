"""Role/tool access contract for the dynamic_validate seat.

The dynamic_validate agent must ground its probe plan in repo source (read
the handler, confirm routes/params) before firing live HTTP probes. This
requires the read-only builtin tools. A whitelist omission (observed on scan
b4faf0a6, 2026-09-16) made every dynamic_validate invocation burn its whole
turn budget on UnauthorizedToolError and silently promote nothing.

These are registry-derived contract tests: they read the real registry, so
any new read-only tool must declare a role policy that includes
``dynamic_validate``, and no write/exec tool may ever add it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from quarry_models.types import BudgetSpec
from quarry_tools.errors import UnauthorizedToolError
from quarry_tools.registry import load_registry
from quarry_tools.runner import ToolRunner

READ_ONLY_TOOLS = ("read_file", "list_dir", "grep", "search_code")
WRITE_OR_EXEC_TOOLS = ("run_in_sandbox",)

_DYN_NOW = datetime(2026, 6, 11, tzinfo=UTC)


def _make_dyn_finding() -> Any:
    from quarry.schemas import (
        CandidateFinding,
        Confidence,
        Severity,
        SourceRef,
        VulnerabilityClass,
    )

    return CandidateFinding(
        id="cf-dyn-1",
        scan_id="scan-dyn-test",
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.IDOR,
        title="IDOR on /users/{id}",
        hypothesis="Unauthenticated user can read another user's profile via GET /users/{id}.",
        affected_component="src/routes/users.py:42",
        root_cause_key="idor-users-id",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_DYN_NOW,
        source_refs=[
            SourceRef(
                file_path="src/routes/users.py",
                start_line=42,
                end_line=50,
                symbol="get_user",
            )
        ],
    )


def _record_event(events: list[tuple[str, dict[str, Any]]]) -> Any:
    def _sink(event_type: str, payload: dict[str, Any]) -> None:
        events.append((event_type, payload))

    return _sink


def _runner(tmp_path: Path, role: str) -> ToolRunner:
    return ToolRunner(
        repo_root=tmp_path,
        role=role,
        registry=load_registry(),
        budget_spec=BudgetSpec(max_cost_usd=10.0),
    )


class TestDynamicValidateReadOnlyAccess:
    @pytest.mark.parametrize("tool_name", READ_ONLY_TOOLS)
    def test_dynamic_validate_allowed_on_read_only_tools(
        self, tmp_path: Path, tool_name: str
    ) -> None:
        registry = load_registry()
        tool = registry[tool_name]
        assert "dynamic_validate" in tool.roles, (
            f"tool '{tool_name}' is missing the dynamic_validate role; roles={tool.roles}"
        )

    @pytest.mark.parametrize("tool_name", READ_ONLY_TOOLS)
    def test_dynamic_validate_read_only_call_does_not_raise_unauthorized(
        self, tmp_path: Path, tool_name: str
    ) -> None:
        runner = _runner(tmp_path, "dynamic_validate")
        (tmp_path / "app.py").write_text("x = 1\n")
        inputs = {
            "read_file": {"path": "app.py"},
            "list_dir": {"path": "."},
            "grep": {"pattern": "x", "scope": "."},
            "search_code": {"pattern": "x", "lang": "python"},
        }[tool_name]
        try:
            runner.run(tool_name, inputs)
        except UnauthorizedToolError as exc:
            pytest.fail(f"dynamic_validate denied read-only tool '{tool_name}': {exc}")
        except Exception:
            # Non-auth failures (missing binary, empty result, etc.) are fine;
            # the contract under test is purely the role gate.
            pass

    @pytest.mark.parametrize("tool_name", WRITE_OR_EXEC_TOOLS)
    def test_dynamic_validate_denied_on_write_or_exec_tools(
        self, tmp_path: Path, tool_name: str
    ) -> None:
        runner = _runner(tmp_path, "dynamic_validate")
        with pytest.raises(UnauthorizedToolError):
            runner.run(tool_name, {"command": "echo hi"})

    def test_registry_tools_covering_dynamic_validate_are_read_only(self) -> None:
        """Every tool granting dynamic_validate must be read-only or http_request."""
        registry = load_registry()
        allowed = {"http_request", *READ_ONLY_TOOLS}
        for name, tool in registry.items():
            if "dynamic_validate" in tool.roles:
                assert name in allowed, (
                    f"tool '{name}' grants dynamic_validate but is not in the "
                    f"read-only/http allow-set {sorted(allowed)}"
                )


class TestUnauthorizedDenialTracking:
    """run_agent_loop must record UnauthorizedToolError denials on the result."""

    def test_denials_recorded_on_loop_result(self, tmp_path: Path) -> None:

        from pydantic import BaseModel

        from quarry_models.loop import ToolCallRequest, run_agent_loop
        from quarry_models.types import BudgetSpec
        from quarry_tools.builtins import BUILTIN_REGISTRY
        from quarry_tools.runner import ToolRunner

        class _Answer(BaseModel):
            result: str = "ok"
            tool_calls: list[Any] = []

        class _DeniedThenAnswer:
            def __init__(self) -> None:
                self._calls = 0

            def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
                self._calls += 1
                if self._calls == 1:
                    parsed = response_model(
                        result="pending",
                        tool_calls=[ToolCallRequest(tool="read_file", inputs={"path": "x.py"})],
                    )
                else:
                    parsed = response_model(result="done", tool_calls=[])
                return type("Resp", (), {"parsed": parsed, "estimated_cost": 0.0})()

        # Role "prove" IS allowed read_file — use a role that is not: "trace"?
        # Simpler: role that has no tools at all.
        runner = ToolRunner(
            repo_root=tmp_path,
            role="dynamic_validate",  # allowed; swap registry to deny instead
            registry={k: v for k, v in BUILTIN_REGISTRY.items()},
            budget_spec=BudgetSpec(max_cost_usd=10.0),
        )
        # Force-deny by mutating the registry entry's roles
        tool = dict(BUILTIN_REGISTRY)["read_file"]
        original_roles = list(tool.roles)
        tool.roles = [r for r in original_roles if r != "dynamic_validate"]
        try:
            result = run_agent_loop(
                client=_DeniedThenAnswer(),  # type: ignore[arg-type]
                role="dynamic_validate",
                agent_kind="dynamic_validate",
                system_prompt="s",
                initial_user_message="u",
                runner=runner,
                budget_spec=BudgetSpec(max_cost_usd=10.0),
                response_model=_Answer,
                max_iterations=5,
            )
        finally:
            tool.roles = original_roles

        assert result.stop_reason == "final_answer"
        assert result.unauthorized_tool_denials == ["read_file"]

    def test_no_denials_when_all_tools_allowed(self, tmp_path: Path) -> None:

        from pydantic import BaseModel

        from quarry_models.loop import run_agent_loop
        from quarry_models.types import BudgetSpec
        from quarry_tools.builtins import BUILTIN_REGISTRY
        from quarry_tools.runner import ToolRunner

        class _Answer(BaseModel):
            result: str = "ok"
            tool_calls: list[Any] = []

        class _ImmediateAnswer:
            def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
                parsed = response_model(result="done", tool_calls=[])
                return type("Resp", (), {"parsed": parsed, "estimated_cost": 0.0})()

        runner = ToolRunner(
            repo_root=tmp_path,
            role="dynamic_validate",
            registry=BUILTIN_REGISTRY,
            budget_spec=BudgetSpec(max_cost_usd=10.0),
        )
        result = run_agent_loop(
            client=_ImmediateAnswer(),  # type: ignore[arg-type]
            role="dynamic_validate",
            agent_kind="dynamic_validate",
            system_prompt="s",
            initial_user_message="u",
            runner=runner,
            budget_spec=BudgetSpec(max_cost_usd=10.0),
            response_model=_Answer,
            max_iterations=5,
        )
        assert result.unauthorized_tool_denials == []


class TestToolAccessDeniedEvent:
    """dynamic_validate_impl must emit a loud event on role-policy denials."""

    def test_event_emitted_on_unauthorized_denials(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        from quarry.schemas import AgentLoopResult
        from quarry_activities.dynamic_validate import (
            DynamicValidateResponse,
            dynamic_validate_impl,
        )
        from quarry_models.mock_client import MockModelClient
        from quarry_models.types import BudgetSpec

        finding = _make_dyn_finding()
        events: list[tuple[str, dict[str, Any]]] = []

        fake_result = AgentLoopResult(
            final_answer=DynamicValidateResponse(verdict="inconclusive"),
            steps=[],
            iterations_used=2,
            total_cost=0.0,
            stop_reason="final_answer",
            unauthorized_tool_denials=["read_file", "grep"],
        )

        with patch("quarry_activities.dynamic_validate.run_agent_loop", return_value=fake_result):
            dynamic_validate_impl(
                finding=finding,
                repo_path=str(tmp_path),
                client=MockModelClient(default=DynamicValidateResponse()),
                max_iterations=3,
                budget_spec=BudgetSpec(max_cost_usd=1.0),
                allowed_hosts=("localhost",),
                event_sink=_record_event(events),
            )

        assert len(events) == 1
        event_type, payload = events[0]
        assert event_type == "dynamic_validate.tool_access_denied"
        assert payload["denied_tools"] == ["read_file", "grep"]
        assert payload["scan_id"] == finding.scan_id
        assert payload["vuln_class"] == finding.vuln_class.value

    def test_no_event_when_no_denials(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        from quarry.schemas import AgentLoopResult
        from quarry_activities.dynamic_validate import (
            DynamicValidateResponse,
            dynamic_validate_impl,
        )
        from quarry_models.mock_client import MockModelClient
        from quarry_models.types import BudgetSpec

        finding = _make_dyn_finding()
        events: list[tuple[str, dict[str, Any]]] = []

        fake_result = AgentLoopResult(
            final_answer=DynamicValidateResponse(verdict="corroborated"),
            steps=[],
            iterations_used=1,
            total_cost=0.0,
            stop_reason="final_answer",
        )

        with patch("quarry_activities.dynamic_validate.run_agent_loop", return_value=fake_result):
            dynamic_validate_impl(
                finding=finding,
                repo_path=str(tmp_path),
                client=MockModelClient(default=DynamicValidateResponse()),
                max_iterations=3,
                budget_spec=BudgetSpec(max_cost_usd=1.0),
                allowed_hosts=("localhost",),
                event_sink=_record_event(events),
            )

        assert events == []
