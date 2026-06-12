"""Tests for the tracer activity (week-14 Thursday).

Written RED first — these fail until src/quarry_activities/tracer.py and
prompts/trace/trace.1.0.0.j2 are created.

Key invariants:
- ``reachable`` verdict: Trace.reachable == REACHABLE, no severity change.
- ``not_reachable`` verdict (Python, non-secrets): severity downgrades one level,
  floor = low.
- ``not_reachable`` on C/C++ ast_grep graph: overridden to ``indeterminate``
  and severity unchanged (the C/C++ override rule must be an explicit branch
  in code, not a prompt instruction).
- Secrets findings (VulnerabilityClass.SECRETS): never downgraded, regardless
  of verdict.
- MockModelClient produces no live I/O.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from quarry.schemas import (
    CallEdge,
    CallGraph,
    CandidateFinding,
    Confidence,
    Provider,
    ReachabilityVerdict,
    Severity,
    Trace,
    VulnerabilityClass,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    scan_id: str = "scan-tracer-test",
    vuln_class: VulnerabilityClass = VulnerabilityClass.COMMAND_INJECTION,
    severity: Severity = Severity.HIGH,
    language: str = "python",
) -> CandidateFinding:
    return CandidateFinding(
        id="cf-trace-1",
        scan_id=scan_id,
        workspace_id="ws-1",
        vuln_class=vuln_class,
        title="Command injection",
        hypothesis="Unsanitized input passed to subprocess",
        affected_component=f"src/runner.{language.split()[0]}",
        confidence=Confidence.HIGH,
        severity=severity,
        created_by="hunter",
        created_at=datetime.now(UTC),
        metadata={"language": language},
    )


def _make_call_graph(
    scan_id: str = "scan-tracer-test",
    index_kind: str = "static",
    edges: list[CallEdge] | None = None,
) -> CallGraph:
    return CallGraph(
        scan_id=scan_id,
        edges=edges or [],
        index_kind=index_kind,
    )


# ---------------------------------------------------------------------------
# TraceResponse model
# ---------------------------------------------------------------------------


class TestTraceResponseModel:
    def test_trace_response_has_required_fields(self) -> None:
        from quarry_activities.tracer import TraceResponse

        resp = TraceResponse()
        assert hasattr(resp, "verdict")
        assert hasattr(resp, "reasons")

    def test_trace_response_defaults(self) -> None:
        from quarry_activities.tracer import TraceResponse

        resp = TraceResponse()
        assert resp.verdict == "indeterminate"
        assert resp.reasons == []

    def test_trace_response_valid_verdicts(self) -> None:
        from quarry_activities.tracer import TraceResponse

        for v in ("reachable", "not_reachable", "indeterminate"):
            resp = TraceResponse(verdict=v)
            assert resp.verdict == v


# ---------------------------------------------------------------------------
# C/C++ indeterminate override
# ---------------------------------------------------------------------------


class TestCppIndeterminateOverride:
    """The override must be explicit code — never a prompt instruction."""

    @pytest.mark.parametrize("language", ["c", "cpp", "c++"])
    def test_not_reachable_cpp_ast_grep_overrides_to_indeterminate(
        self, tmp_path: Path, language: str
    ) -> None:
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding(language=language)
        call_graph = _make_call_graph(index_kind="ast_grep")
        client = MockModelClient(default=TraceResponse(verdict="not_reachable"))

        trace = tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        assert trace.reachable == ReachabilityVerdict.INDETERMINATE, (
            f"C/C++ ast_grep not_reachable must be overridden to indeterminate "
            f"(got: {trace.reachable})"
        )

    @pytest.mark.parametrize("language", ["c", "cpp", "c++"])
    def test_cpp_ast_grep_indeterminate_no_severity_change(
        self, tmp_path: Path, language: str
    ) -> None:
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding(language=language, severity=Severity.HIGH)
        call_graph = _make_call_graph(index_kind="ast_grep")
        client = MockModelClient(default=TraceResponse(verdict="not_reachable"))

        trace = tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        # Severity must be unchanged when verdict is forced to indeterminate
        assert finding.severity == Severity.HIGH, "Severity must not change on indeterminate"
        # Trace carries the overridden verdict
        assert trace.reachable == ReachabilityVerdict.INDETERMINATE

    def test_not_reachable_python_ast_grep_not_overridden(self, tmp_path: Path) -> None:
        """Python ast_grep is NOT in the C/C++ language set — must not override."""
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding(language="python")
        call_graph = _make_call_graph(index_kind="ast_grep")
        client = MockModelClient(default=TraceResponse(verdict="not_reachable"))

        trace = tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        assert trace.reachable == ReachabilityVerdict.NOT_REACHABLE

    def test_not_reachable_scip_not_overridden(self, tmp_path: Path) -> None:
        """SCIP index_kind is not in UNRESOLVED_GRAPH_KINDS — C finding not overridden."""
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding(language="c")
        call_graph = _make_call_graph(index_kind="scip")
        client = MockModelClient(default=TraceResponse(verdict="not_reachable"))

        trace = tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        assert trace.reachable == ReachabilityVerdict.NOT_REACHABLE


# ---------------------------------------------------------------------------
# Severity re-ranking
# ---------------------------------------------------------------------------


class TestSeverityReranking:
    @pytest.mark.parametrize(
        ("initial", "expected"),
        [
            (Severity.CRITICAL, Severity.HIGH),
            (Severity.HIGH, Severity.MEDIUM),
            (Severity.MEDIUM, Severity.LOW),
            (Severity.LOW, Severity.LOW),  # floor = low
            (Severity.INFO, Severity.INFO),  # INFO not in the regular ladder — unchanged
        ],
    )
    def test_not_reachable_downgrades_one_level(
        self, tmp_path: Path, initial: Severity, expected: Severity
    ) -> None:
        from quarry_activities.tracer import downgrade_severity

        result = downgrade_severity(initial)
        assert result == expected

    def test_not_reachable_python_downgrades_severity(self, tmp_path: Path) -> None:
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding(language="python", severity=Severity.HIGH)
        call_graph = _make_call_graph(index_kind="ast_grep")
        client = MockModelClient(default=TraceResponse(verdict="not_reachable"))

        tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        # Severity should have been downgraded in place
        assert finding.severity == Severity.MEDIUM

    def test_reachable_verdict_no_severity_change(self, tmp_path: Path) -> None:
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding(severity=Severity.HIGH)
        call_graph = _make_call_graph(index_kind="static")
        client = MockModelClient(default=TraceResponse(verdict="reachable"))

        tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        assert finding.severity == Severity.HIGH

    def test_indeterminate_verdict_no_severity_change(self, tmp_path: Path) -> None:
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding(severity=Severity.MEDIUM)
        call_graph = _make_call_graph(index_kind="static")
        client = MockModelClient(default=TraceResponse(verdict="indeterminate"))

        tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        assert finding.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Secrets exemption
# ---------------------------------------------------------------------------


class TestSecretsExemption:
    def test_secrets_not_downgraded_on_not_reachable(self, tmp_path: Path) -> None:
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding(
            vuln_class=VulnerabilityClass.SECRETS,
            severity=Severity.CRITICAL,
        )
        call_graph = _make_call_graph(index_kind="static")
        client = MockModelClient(default=TraceResponse(verdict="not_reachable"))

        tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        assert finding.severity == Severity.CRITICAL, (
            "Secrets findings must never be downgraded by tracer verdict"
        )

    def test_secrets_trace_verdict_still_recorded(self, tmp_path: Path) -> None:
        """Even when severity is exempt, the trace verdict must be recorded."""
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding(vuln_class=VulnerabilityClass.SECRETS)
        call_graph = _make_call_graph(index_kind="static")
        client = MockModelClient(default=TraceResponse(verdict="not_reachable"))

        trace = tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        assert trace.reachable == ReachabilityVerdict.NOT_REACHABLE


# ---------------------------------------------------------------------------
# Trace return value
# ---------------------------------------------------------------------------


class TestTracerImplReturnValue:
    def test_returns_trace_instance(self, tmp_path: Path) -> None:
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding()
        call_graph = _make_call_graph()
        client = MockModelClient(default=TraceResponse(verdict="reachable"))

        result = tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        assert isinstance(result, Trace)

    def test_trace_has_correct_finding_id(self, tmp_path: Path) -> None:
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding()
        call_graph = _make_call_graph()
        client = MockModelClient(default=TraceResponse(verdict="reachable"))

        trace = tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        assert trace.finding_id == finding.id
        assert trace.scan_id == finding.scan_id

    def test_reachable_verdict_in_trace(self, tmp_path: Path) -> None:
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding()
        call_graph = _make_call_graph()
        client = MockModelClient(default=TraceResponse(verdict="reachable"))

        trace = tracer_impl(
            finding=finding,
            call_graph=call_graph,
            repo_path=str(tmp_path),
            panel={},
            client=client,
        )

        assert trace.reachable == ReachabilityVerdict.REACHABLE


# ---------------------------------------------------------------------------
# No live I/O
# ---------------------------------------------------------------------------


class TestTracerImplNoLiveIO:
    def test_mock_does_no_subprocess(self, tmp_path: Path) -> None:
        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding()
        call_graph = _make_call_graph()
        client = MockModelClient(default=TraceResponse(verdict="indeterminate"))

        with patch("subprocess.run") as mock_run:
            tracer_impl(
                finding=finding,
                call_graph=call_graph,
                repo_path=str(tmp_path),
                panel={},
                client=client,
            )
            mock_run.assert_not_called()

    def test_mock_does_no_socket(self, tmp_path: Path) -> None:
        import socket

        from quarry_activities.tracer import TraceResponse, tracer_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding()
        call_graph = _make_call_graph()
        client = MockModelClient(default=TraceResponse(verdict="indeterminate"))

        original_connect = socket.socket.connect
        connections: list[Any] = []

        def _no_connect(self: Any, addr: Any) -> None:
            connections.append(addr)
            raise RuntimeError("Socket connect forbidden in tracer_impl")

        socket.socket.connect = _no_connect  # type: ignore[method-assign]
        try:
            tracer_impl(
                finding=finding,
                call_graph=call_graph,
                repo_path=str(tmp_path),
                panel={},
                client=client,
            )
        finally:
            socket.socket.connect = original_connect  # type: ignore[method-assign]

        assert connections == [], f"tracer_impl opened socket connections: {connections}"


# ---------------------------------------------------------------------------
# Named constants
# ---------------------------------------------------------------------------


class TestNamedConstants:
    def test_unresolved_graph_kinds_constant_exists(self) -> None:
        from quarry_activities.tracer import UNRESOLVED_GRAPH_KINDS

        assert isinstance(UNRESOLVED_GRAPH_KINDS, (set, frozenset))
        assert "ast_grep" in UNRESOLVED_GRAPH_KINDS

    def test_unresolved_graph_languages_constant_exists(self) -> None:
        from quarry_activities.tracer import UNRESOLVED_GRAPH_LANGUAGES

        assert isinstance(UNRESOLVED_GRAPH_LANGUAGES, (set, frozenset))
        for lang in ("c", "cpp", "c++"):
            assert lang in UNRESOLVED_GRAPH_LANGUAGES

    def test_secrets_exempt_constant_exists(self) -> None:
        from quarry.schemas import VulnerabilityClass
        from quarry_activities.tracer import SEVERITY_EXEMPT_VULN_CLASSES

        assert isinstance(SEVERITY_EXEMPT_VULN_CLASSES, (set, frozenset))
        assert VulnerabilityClass.SECRETS in SEVERITY_EXEMPT_VULN_CLASSES


# ---------------------------------------------------------------------------
# Activity interface
# ---------------------------------------------------------------------------


class TestTracerActivity:
    def test_tracer_activity_exists_and_is_callable(self) -> None:
        from quarry_activities.tracer import tracer_activity

        assert callable(tracer_activity)

    def test_tracer_activity_returns_dict_for_mock_panel(self, tmp_path: Path) -> None:
        from quarry.panel_config import RoleConfig
        from quarry_activities.tracer import tracer_activity

        finding = _make_finding()
        call_graph = _make_call_graph()
        mock_panel_json = RoleConfig(provider=Provider.MOCK, model="mock").model_dump_json()

        result = tracer_activity(
            finding=finding.model_dump(mode="json"),
            call_graph=call_graph.model_dump(mode="json"),
            repo_path=str(tmp_path),
            panel_json=mock_panel_json,
            max_iterations=2,
        )

        assert isinstance(result, dict)
        assert "reachable" in result

    def test_tracer_activity_mock_does_not_call_build_model_client(self, tmp_path: Path) -> None:
        from quarry.panel_config import RoleConfig
        from quarry_activities.tracer import tracer_activity

        finding = _make_finding()
        call_graph = _make_call_graph()
        mock_panel_json = RoleConfig(provider=Provider.MOCK, model="mock").model_dump_json()

        with patch("quarry_activities.tracer.build_model_client") as mock_build:
            tracer_activity(
                finding=finding.model_dump(mode="json"),
                call_graph=call_graph.model_dump(mode="json"),
                repo_path=str(tmp_path),
                panel_json=mock_panel_json,
                max_iterations=2,
            )
            mock_build.assert_not_called()
