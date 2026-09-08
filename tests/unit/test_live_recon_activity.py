"""Live-recon agent — TDD for task 2.1 (live-exploitation-loop).

The live-recon agent consumes code-recon output (an ``ArchitectureDoc``) plus an
authorized live target and produces a *live attack map*: reachable endpoints
correlated with the code entry points they exercise. It never opens a socket in
the loop — it proposes ``http_request`` specs the driver dispatches (propose→
dispatch, per design).

Two behaviours are locked in here:

- **Authorized:** given code entry points, the agent returns attack-map entries
  correlated with those entry points, and runs the loop (a model invocation is
  recorded) without any live I/O in agent context.
- **Unauthorized:** the stage is a fail-closed no-op — it runs no loop, records no
  invocation, and proposes no ``http_request``. No traffic without authorization.
"""

from __future__ import annotations

from quarry.schemas import ArchitectureDoc, EntryPoint
from quarry_activities.live_recon import (
    LiveAttackMapEntry,
    LiveReconResponse,
    live_recon_active,
    live_recon_impl,
)
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec


def _architecture() -> ArchitectureDoc:
    return ArchitectureDoc(
        repo_languages=["python"],
        primary_language="python",
        repo_type="web_service",
        entry_points=[
            EntryPoint(
                repo="app",
                file="app/users.py",
                function="get_user",
                kind="http_handler",
            ),
            EntryPoint(
                repo="app",
                file="app/admin.py",
                function="admin_panel",
                kind="http_handler",
            ),
        ],
        attack_surface_summary="A small user-facing web service with an admin panel.",
    )


def _canned_attack_map() -> LiveReconResponse:
    return LiveReconResponse(
        attack_map=[
            LiveAttackMapEntry(
                method="GET",
                path="/users/1",
                code_file="app/users.py",
                code_function="get_user",
                auth_required=False,
                notes="IDOR candidate",
            )
        ],
        reasons=["correlated /users/{id} handler with get_user"],
        proposed_http_specs=[{"method": "GET", "path": "/users/1"}],
        tool_calls=[],
    )


class TestLiveReconGate:
    def test_active_requires_authorization_and_target(self) -> None:
        assert live_recon_active(authorized=True, target_url="http://localhost:8000") is True
        assert live_recon_active(authorized=False, target_url="http://localhost:8000") is False
        assert live_recon_active(authorized=True, target_url=None) is False
        assert live_recon_active(authorized=True, target_url="") is False

    def test_unauthorized_is_a_noop(self) -> None:
        client = MockModelClient(default=_canned_attack_map())
        result = live_recon_impl(
            architecture=_architecture(),
            repo_path=".",
            client=client,
            authorized=False,
            target_summary="http://localhost:8000",
            allowed_hosts=["localhost"],
            budget_spec=BudgetSpec(max_cost_usd=1.0),
        )
        # Fail-closed no-op: no loop, no invocation, no proposed egress.
        assert result.attack_map == []
        assert result.proposed_http_specs == []
        assert client.invocations == []


class TestLiveReconAuthorized:
    def test_produces_map_correlated_with_code_entry_points(self) -> None:
        arch = _architecture()
        client = MockModelClient(default=_canned_attack_map())
        result = live_recon_impl(
            architecture=arch,
            repo_path=".",
            client=client,
            authorized=True,
            target_summary="http://localhost:8000",
            allowed_hosts=["localhost"],
            budget_spec=BudgetSpec(max_cost_usd=1.0),
        )
        assert isinstance(result, LiveReconResponse)
        assert result.attack_map, "expected a live attack map"
        # Every mapped entry cites a real code entry point from the architecture.
        code_fns = {(e.file, e.function) for e in arch.entry_points}
        for entry in result.attack_map:
            assert (entry.code_file, entry.code_function) in code_fns
        # The loop ran (an invocation was recorded) with no socket I/O in agent context.
        assert client.invocations, "expected the agent loop to run"
