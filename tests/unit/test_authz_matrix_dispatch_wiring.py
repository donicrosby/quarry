"""W14 persona-dispatch + matrix-gate wiring (spec Group 2 / Group 6).

RED-by-construction coverage for the dispatch/gate/hunt seams the W14 matrix adds
to ``run_scan.py``. The repo's convention for workflow dispatch logic — which the
Temporal sandbox makes awkward to drive end to end (no e2e fixture wires a
hunt/validate MockModelClient; see ``test_lifecycle_hooks_e2e.py``) — is
**pure-helper tests plus source-level contract assertions** on the workflow body
(see ``test_workflow_differential_dispatch.py``). These tests lock:

- an explicit ``auth_profile`` bypasses persona selection;
- a no-match request is refused before egress with a recorded reason;
- zero personas behave exactly like the pre-change path (no persona refusals);
- the VALIDATION dynamic-validation and live-prove egress paths apply no persona
  selection (single-authorization semantics unchanged);
- the matrix stage is gated by the live track + personas, never by
  ``dynamic_validation_enabled``;
- matrix-conditioned hunt tasks merge into the next round's hunt queue (the SF-B
  ``round_tasks`` consumption seam) — reverting it to ``agent_tasks`` only would
  otherwise pass the whole suite.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from quarry.schemas import (
    AgentTask,
    ArtifactKind,
    ArtifactRef,
    ExploitStep,
    HttpRequestSpec,
    PersonaScope,
    RedactionStatus,
    TargetAuthorization,
)
from quarry_activities.authz_matrix import (
    AuthzMatrixPersona,
    AuthzMatrixResult,
    AuthzViolation,
    build_authz_hunt_tasks,
)
from quarry_workflows.coverage_loop import cell_key, compose_round_tasks, dedup_new_tasks
from quarry_workflows.run_scan import (
    RunScanInput,
    authz_matrix_active,
    plan_persona_dispatch,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_SCAN = REPO_ROOT / "src" / "quarry_workflows" / "run_scan.py"
_AUTHZ_MATRIX = REPO_ROOT / "src" / "quarry_activities" / "authz_matrix.py"

_NOW = datetime(2026, 7, 31, tzinfo=UTC)
_HOST = "app.example.com"


def _authz(personas: list[PersonaScope]) -> TargetAuthorization:
    base: dict[str, Any] = {
        "id": "auth-1",
        "target_id": "tgt-1",
        "workspace_id": "local",
        "authorized_by": "secops@example.com",
        "allowed_hosts": [_HOST],
        "allowed_repo_paths": ["/"],
        "created_at": _NOW,
        "personas": personas,
    }
    return TargetAuthorization.model_validate(base)


def _persona(**overrides: Any) -> PersonaScope:
    base: dict[str, Any] = {
        "name": "user",
        "profile_ref": "user-token",
        "allowed_hosts": [_HOST],
        "privilege_level": "user",
    }
    base.update(overrides)
    return PersonaScope.model_validate(base)


def _spec(path: str, *, auth_profile: str | None = None) -> HttpRequestSpec:
    return HttpRequestSpec(method="GET", path=path, auth_profile=auth_profile)


def _source() -> str:
    return _RUN_SCAN.read_text(encoding="utf-8")


def _function_ast(source: str, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    msg = f"function {name!r} not found"
    raise AssertionError(msg)


def _function_source(source: str, name: str) -> str:
    """Source text of the first function/method named ``name`` (via the AST)."""
    lines = source.splitlines()
    node = _function_ast(source, name)
    return "\n".join(lines[node.lineno - 1 : node.end_lineno or node.lineno])


def _code_without_docstring(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """The function body with its leading docstring dropped (unparsed)."""
    body = list(node.body)
    first = body[0] if body else None
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        body = body[1:]
    return "\n".join(ast.unparse(stmt) for stmt in body)


class TestPlanPersonaDispatch:
    def test_matching_persona_sets_explicit_profile_ref(self) -> None:
        authz = _authz([_persona(name="user", profile_ref="user-token")])
        out, refusal = plan_persona_dispatch(
            _spec("/dashboard"), authz, host=_HOST, path="/dashboard"
        )
        assert refusal is None
        assert out.auth_profile == "user-token"

    def test_explicit_auth_profile_bypasses_persona_selection(self) -> None:
        """An explicit ``auth_profile`` wins even on a path no persona covers."""
        authz = _authz([_persona(allowed_paths=["/admin"])])
        out, refusal = plan_persona_dispatch(
            _spec("/public", auth_profile="explicit"), authz, host=_HOST, path="/public"
        )
        assert refusal is None
        assert out.auth_profile == "explicit"

    def test_no_match_refusal_reason_is_recorded_on_the_step(self) -> None:
        authz = _authz([_persona(allowed_paths=["/admin"])])
        out, refusal = plan_persona_dispatch(_spec("/public"), authz, host=_HOST, path="/public")
        assert refusal is not None
        assert "persona" in refusal
        # The refusal is recorded on an ExploitStep with dispatched=False (same
        # shape as the out-of-scope refusal).
        step = ExploitStep(
            order=0,
            intent="exploit",
            request_spec=out,
            dispatched=False,
            confirmed=False,
            notes=refusal,
        )
        assert step.dispatched is False
        assert step.notes == refusal

    def test_zero_personas_emits_no_persona_refusal(self) -> None:
        """Backward compatibility: the pre-change path never persona-refuses."""
        authz = _authz([])
        out, refusal = plan_persona_dispatch(_spec("/public"), authz, host=_HOST, path="/public")
        assert refusal is None
        assert out.auth_profile is None

    def test_unauthenticated_persona_keeps_none_profile(self) -> None:
        authz = _authz([_persona(name="anon", profile_ref=None, privilege_level="unauthenticated")])
        out, refusal = plan_persona_dispatch(_spec("/public"), authz, host=_HOST, path="/public")
        assert refusal is None
        assert out.auth_profile is None


class TestDispatchWiringSource:
    def test_persona_dispatch_helper_used_only_in_the_live_exploit_chain(self) -> None:
        source = _source()
        # def + exactly one call site.
        assert source.count("plan_persona_dispatch(") == 2
        # persona_for_request is reached only through the helper.
        assert source.count("persona_for_request(") == 1
        assert "persona_for_request(" in _function_source(source, "plan_persona_dispatch")

    def test_refusal_branch_appends_an_exploit_step(self) -> None:
        body = _function_source(_source(), "_exploit_class_chain")
        assert "persona_refusal" in body
        assert "dispatched=False" in body
        assert "notes=persona_refusal" in body

    def test_validation_and_prove_egress_apply_no_persona_selection(self) -> None:
        source = _source()
        for name in ("_dispatch_dynamic_probe", "build_prove_dispatch_inputs"):
            body = _function_source(source, name)
            assert "persona" not in body.lower(), (
                f"{name} must keep single-authorization semantics — no persona selection"
            )


class TestAuthzMatrixGate:
    def test_matrix_runs_without_dynamic_validation(self) -> None:
        inp = RunScanInput(
            repo_path="/tmp/repo",
            scan_id="s1",
            live_exploit_enabled=True,
            target_url=f"http://{_HOST}",
            dynamic_validation_enabled=False,
        )
        authz = _authz([_persona()])
        assert inp.dynamic_validation_enabled is False
        assert (
            authz_matrix_active(
                enabled=inp.live_exploit_enabled,
                target_url=inp.target_url,
                authorization=authz,
            )
            is True
        )

    def test_gate_helper_ignores_the_dynamic_validation_flag(self) -> None:
        node = _function_ast(_source(), "authz_matrix_active")
        assert "dynamic_validation_enabled" not in _code_without_docstring(node)

    def test_zero_personas_skips_the_matrix(self) -> None:
        assert (
            authz_matrix_active(
                enabled=True, target_url=f"http://{_HOST}", authorization=_authz([])
            )
            is False
        )

    def test_inactive_authorization_skips_the_matrix(self) -> None:
        blank = _authz([_persona()]).model_copy(update={"authorized_by": ""})
        assert (
            authz_matrix_active(enabled=True, target_url=f"http://{_HOST}", authorization=blank)
            is False
        )


class TestMatrixTaskQueueSeam:
    def test_matrix_tasks_merge_into_the_next_round_queue(self) -> None:
        """SF-B: reverting to agent_tasks-only must break this guard.

        Two layers: the workflow must pass ``matrix_tasks`` to the round-queue
        composer, and the composer itself must include them (its own behavioural
        test above fails if the merge is dropped).
        """
        body = _function_source(_source(), "_run")
        assert "compose_round_tasks(agent_tasks, matrix_tasks)" in body, (
            "the round queue must be composed from agent tasks AND matrix tasks"
        )
        assert "all_agent_tasks.extend(matrix_tasks)" in body

    def test_completed_event_carries_counts_and_error_cells(self) -> None:
        source = _source()
        assert '"authz_matrix.started"' in source
        assert '"authz_matrix.completed"' in source
        assert '"error_cell_count"' in source


class TestLoginFlowInheritsSharedPath:
    def test_matrix_activity_adds_no_credential_handling(self) -> None:
        """B3: the matrix dispatches through the shared egress path and owns no
        credential resolution / caching of its own — login-flow profiles inherit
        the shared-path resolution (``dynamic_http``)."""
        source = _AUTHZ_MATRIX.read_text(encoding="utf-8")
        assert "http_request_activity" in source
        assert "CredentialCache" not in source
        assert "resolve_credentials" not in source


def _matrix_artifact() -> ArtifactRef:
    return ArtifactRef(
        id="art-matrix",
        uri="file:///tmp/authz_matrix/matrix.json",
        kind=ArtifactKind.AUTHZ_MATRIX,
        content_type="application/json",
        sha256="0" * 64,
        size_bytes=42,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=_NOW,
    )


class TestFreshRunHuntsMatrixTask:
    """G6 fresh-run hunting (the r2 SF-B verification): a flagged endpoint is
    hunted by the coverage loop from round 0, not merely recorded."""

    def _matrix_tasks(self) -> list[AgentTask]:
        violation = AuthzViolation(
            kind="unauth_access",
            endpoint_path="/admin/users",
            endpoint_method="GET",
            persona="anon",
            privilege_level="unauthenticated",
            status_code=200,
        )
        matrix = AuthzMatrixResult(
            scan_id="s1",
            personas=[AuthzMatrixPersona(name="anon", privilege_level="unauthenticated")],
            rows=[],
            artifact_ref=_matrix_artifact(),
        )
        return build_authz_hunt_tasks(
            [violation], matrix, scan_id="s1", round_index=0, created_at=_NOW
        )

    def _recon_task(self) -> AgentTask:
        return AgentTask(
            id="recon-1",
            scan_id="s1",
            role="hunt",
            task_name="recon-task",
            task_prompt="hunt the recon endpoint",
            scope="/dashboard",
            round_index=0,
            status="pending",
            created_at=_NOW,
        )

    def test_flagged_endpoint_reaches_the_first_round_hunt_queue(self) -> None:
        matrix_tasks = self._matrix_tasks()
        assert matrix_tasks, "a violating matrix must mint a matrix-conditioned hunt task"

        round_tasks = compose_round_tasks([self._recon_task()], matrix_tasks)

        hunted = [t for t in round_tasks if t.scope == "/admin/users"]
        assert len(hunted) == 1, "the flagged endpoint must be among the round's hunted tasks"
        assert "/admin/users" in hunted[0].task_prompt
        assert hunted[0].source == "authz-matrix"

    def test_matrix_cells_survive_dedup_and_do_not_shadow_gapfill(self) -> None:
        matrix_tasks = self._matrix_tasks()
        # Not deduped against an empty hunted set (round 0).
        assert [t.id for t in dedup_new_tasks(matrix_tasks, set())] == [t.id for t in matrix_tasks]
        # A distinct source keeps matrix cells out of the gapfill dedup namespace.
        gapfill_twin = matrix_tasks[0].model_copy(update={"source": "gapfill"})
        assert cell_key(gapfill_twin) != cell_key(matrix_tasks[0])
