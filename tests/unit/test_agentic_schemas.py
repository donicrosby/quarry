"""Round-trip tests for Week 11 agentic schemas.

Written RED first — these fail until the new schemas are added to
quarry/schemas.py and the existing EntryPoint.kind literal is extended.
"""

from __future__ import annotations

import json

import pytest

from quarry.schemas import (
    AgentLoopResult,
    AgentStep,
    ArchitectureDoc,
    BuildCommand,
    EntryPoint,
    ScanProfile,
    ScopeExclusion,
    Subsystem,
    SubsystemAssignment,
    TargetAuthorization,
    TrustBoundary,
    VulnerabilityClass,
)

# ---------------------------------------------------------------------------
# ScopeExclusion
# ---------------------------------------------------------------------------


def test_scope_exclusion_round_trip() -> None:
    exc = ScopeExclusion(kind="route", value="/admin", reason="out of scope", block_dynamic=True)
    data = exc.model_dump()
    restored = ScopeExclusion.model_validate(data)
    assert restored.kind == "route"
    assert restored.value == "/admin"
    assert restored.reason == "out of scope"
    assert restored.block_dynamic is True


def test_scope_exclusion_json_round_trip() -> None:
    exc = ScopeExclusion(kind="note", value="skip billing", reason="no auth", block_dynamic=False)
    restored = ScopeExclusion.model_validate_json(exc.model_dump_json())
    assert restored == exc


# ---------------------------------------------------------------------------
# EntryPoint.kind extended literal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind",
    [
        "http_handler",
        "cli_arg",
        "library_export",
        "fuzz_harness",
        "main",
        "message_handler",
        "unknown",
    ],
)
def test_entry_point_kind_accepts_all_kinds(kind: str) -> None:
    ep = EntryPoint(repo="my-repo", file="app.go", function="main", kind=kind)  # type: ignore[arg-type]
    assert ep.kind == kind


def test_entry_point_kind_new_values_round_trip() -> None:
    ep = EntryPoint(repo="r", file="f.js", function="handler", kind="fuzz_harness")  # type: ignore[arg-type]
    restored = EntryPoint.model_validate_json(ep.model_dump_json())
    assert restored.kind == "fuzz_harness"


# ---------------------------------------------------------------------------
# SubsystemAssignment (frozen)
# ---------------------------------------------------------------------------


def test_subsystem_assignment_round_trip() -> None:
    sa = SubsystemAssignment(
        name="api",
        root_paths=["src/api"],
        languages=["javascript"],
        responsibility="HTTP request handling",
    )
    data = sa.model_dump()
    restored = SubsystemAssignment.model_validate(data)
    assert restored.name == "api"
    assert restored.languages == ["javascript"]


def test_subsystem_assignment_is_frozen() -> None:
    sa = SubsystemAssignment(
        name="api",
        root_paths=["src/api"],
        languages=["go"],
        responsibility="grpc server",
    )
    with pytest.raises((ValueError, AttributeError, TypeError)):
        sa.name = "modified"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TrustBoundary
# ---------------------------------------------------------------------------


def test_trust_boundary_round_trip() -> None:
    tb = TrustBoundary(
        name="public-api",
        description="The HTTP surface exposed to the internet",
        crosses=["user-db", "cache"],
        auth_model="bearer-token",
    )
    restored = TrustBoundary.model_validate_json(tb.model_dump_json())
    assert restored == tb
    assert restored.auth_model == "bearer-token"


# ---------------------------------------------------------------------------
# BuildCommand
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("purpose", ["build", "test", "run", "fuzz", "install"])
def test_build_command_all_purposes(purpose: str) -> None:
    bc = BuildCommand(purpose=purpose, command="make " + purpose, working_dir=".")  # type: ignore[arg-type]
    assert bc.purpose == purpose


def test_build_command_round_trip() -> None:
    bc = BuildCommand(purpose="run", command="node app.js", working_dir=".")  # type: ignore[arg-type]
    restored = BuildCommand.model_validate_json(bc.model_dump_json())
    assert restored == bc


# ---------------------------------------------------------------------------
# Subsystem
# ---------------------------------------------------------------------------


def test_subsystem_round_trip() -> None:
    ep = EntryPoint(repo="r", file="app.js", function="listen", kind="http_handler")  # type: ignore[arg-type]
    sub = Subsystem(
        name="web",
        root_paths=["src/web"],
        languages=["javascript"],
        responsibility="user-facing API",
        entry_points=[ep],
        notes="Express app",
    )
    data = json.loads(sub.model_dump_json())
    restored = Subsystem.model_validate(data)
    assert restored.name == "web"
    assert restored.entry_points[0].kind == "http_handler"


# ---------------------------------------------------------------------------
# ArchitectureDoc
# ---------------------------------------------------------------------------


def test_architecture_doc_all_fields_present() -> None:
    ep = EntryPoint(repo="r", file="main.go", function="main", kind="main")  # type: ignore[arg-type]
    sub = Subsystem(
        name="core",
        root_paths=["."],
        languages=["go"],
        responsibility="main server",
        entry_points=[ep],
        notes="",
    )
    tb = TrustBoundary(name="api", description="public surface", crosses=[], auth_model="none")
    bc = BuildCommand(purpose="build", command="go build .", working_dir=".")  # type: ignore[arg-type]
    doc = ArchitectureDoc(
        repo_languages=["go"],
        primary_language="go",
        repo_type="web_service",
        subsystems=[sub],
        entry_points=[ep],
        trust_boundaries=[tb],
        build_commands=[bc],
        attack_surface_summary="One HTTP handler exposed publicly.",
        transcript_refs=[],
    )
    assert doc.primary_language == "go"
    assert doc.repo_type == "web_service"
    assert len(doc.subsystems) == 1
    assert len(doc.trust_boundaries) == 1
    assert len(doc.build_commands) == 1


def test_architecture_doc_round_trip() -> None:
    ep = EntryPoint(repo="r", file="app.js", function="app", kind="http_handler")  # type: ignore[arg-type]
    sub = Subsystem(
        name="api",
        root_paths=["src"],
        languages=["javascript"],
        responsibility="REST API",
        entry_points=[ep],
        notes="",
    )
    doc = ArchitectureDoc(
        repo_languages=["javascript"],
        primary_language="javascript",
        repo_type="web_service",
        subsystems=[sub],
        entry_points=[ep],
        trust_boundaries=[],
        build_commands=[],
        attack_surface_summary="Express REST API",
        transcript_refs=["step-1"],
    )
    restored = ArchitectureDoc.model_validate_json(doc.model_dump_json())
    assert restored.primary_language == "javascript"
    assert restored.transcript_refs == ["step-1"]


# ---------------------------------------------------------------------------
# AgentStep
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind",
    ["orchestrator", "subsystem", "synthesis", "hunt", "validate", "prove", "trace", "gapfill"],
)
def test_agent_step_all_agent_kinds(kind: str) -> None:
    step = AgentStep(
        agent_kind=kind,  # type: ignore[arg-type]
        iteration=1,
        tool_calls=["read_file"],
        model_invocation_id="inv-1",
        estimated_cost=0.001,
    )
    assert step.agent_kind == kind


def test_agent_step_round_trip() -> None:
    step = AgentStep(
        agent_kind="orchestrator",
        iteration=2,
        tool_calls=["list_dir", "read_file"],
        model_invocation_id="inv-42",
        estimated_cost=0.002,
    )
    restored = AgentStep.model_validate_json(step.model_dump_json())
    assert restored == step
    assert restored.iteration == 2


# ---------------------------------------------------------------------------
# AgentLoopResult
# ---------------------------------------------------------------------------


def test_agent_loop_result_round_trip_no_answer() -> None:
    result = AgentLoopResult(
        final_answer=None,
        steps=[],
        iterations_used=20,
        total_cost=0.05,
        stop_reason="max_iterations",
    )
    restored = AgentLoopResult.model_validate(result.model_dump())
    assert restored.stop_reason == "max_iterations"
    assert restored.final_answer is None


@pytest.mark.parametrize(
    "stop_reason",
    ["final_answer", "max_iterations", "budget_exceeded", "guard_triggered"],
)
def test_agent_loop_result_stop_reasons(stop_reason: str) -> None:
    result = AgentLoopResult(
        final_answer=None,
        steps=[],
        iterations_used=1,
        total_cost=0.0,
        stop_reason=stop_reason,  # type: ignore[arg-type]
    )
    assert result.stop_reason == stop_reason


# ---------------------------------------------------------------------------
# ScanProfile gains scope_exclusions
# ---------------------------------------------------------------------------


def test_scan_profile_has_scope_exclusions() -> None:
    exc = ScopeExclusion(
        kind="route", value="/admin", reason="no auth configured yet", block_dynamic=True
    )
    profile = ScanProfile(
        id="p1",
        name="test",
        vuln_classes=[VulnerabilityClass.SECRETS],
        scope_exclusions=[exc],
    )
    assert len(profile.scope_exclusions) == 1
    assert profile.scope_exclusions[0].value == "/admin"


def test_scan_profile_scope_exclusions_default_empty() -> None:
    profile = ScanProfile(id="p2", name="test", vuln_classes=[])
    assert profile.scope_exclusions == []


# ---------------------------------------------------------------------------
# TargetAuthorization gains do_not_test
# ---------------------------------------------------------------------------


def test_target_authorization_has_do_not_test() -> None:
    from datetime import UTC, datetime

    ta = TargetAuthorization(
        id="ta1",
        target_id="t1",
        workspace_id="ws1",
        authorized_by="alice",
        allowed_hosts=["localhost"],
        allowed_repo_paths=["."],
        do_not_test=["/admin", "/billing"],
        created_at=datetime.now(UTC),
    )
    assert ta.do_not_test == ["/admin", "/billing"]


def test_target_authorization_do_not_test_default_empty() -> None:
    from datetime import UTC, datetime

    ta = TargetAuthorization(
        id="ta2",
        target_id="t2",
        workspace_id="ws2",
        authorized_by="bob",
        allowed_hosts=["localhost"],
        allowed_repo_paths=["."],
        created_at=datetime.now(UTC),
    )
    assert ta.do_not_test == []
