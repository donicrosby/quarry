"""Live-recon activity — agentic live attack-map construction (Shannon pillar).

The live-recon agent takes the code-recon output (an ``ArchitectureDoc``) plus an
authorized live target and builds a *live attack map*: reachable endpoints
correlated with the code entry points they exercise. It is the app-centric
precursor to the exploitation loop — it turns "what the code exposes" into "what
the running app actually answers", grounding later exploitation in real behaviour.

It NEVER opens a socket inside the loop — the ``http_request`` tool returns a
dispatch payload only, and the driver performs the single allow-listed egress
(propose→dispatch, ADR-017 + design D6). The stage is fail-closed: without live
authorization it is a no-op that runs no loop and proposes no request.
"""

from __future__ import annotations

import contextvars
import json
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from temporalio import activity

from quarry.panel_config import DEFAULT_PANEL, RoleConfig
from quarry.schemas import ArchitectureDoc, Provider
from quarry_activities.event_sink import make_event_sink
from quarry_activities.model_cost import persist_model_invocations
from quarry_artifacts.store import persist_seed_prompt
from quarry_models.factory import build_model_client
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.rate_limit import get_limiter
from quarry_models.types import BudgetSpec, PromptProvenance, ProviderPolicy
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_tools.registry import load_registry
from quarry_tools.runner import ToolRunner


class LiveAttackMapEntry(BaseModel):
    """One reachable endpoint on the live target, correlated with code.

    ``code_file`` / ``code_function`` cite the ``EntryPoint`` in the recon
    ``ArchitectureDoc`` that this live endpoint exercises, so downstream
    exploitation is grounded in both the running app and its source.
    """

    method: str
    path: str
    code_file: str = ""
    code_function: str = ""
    auth_required: bool = False
    notes: str = ""


class LiveReconResponse(BaseModel):
    """Model output schema for the live-recon agent loop.

    The agent populates ``attack_map`` with live-reachable endpoints correlated to
    code entry points, and ``proposed_http_specs`` with the probes it wants the
    driver to dispatch (propose→dispatch — the loop never opens a socket).
    """

    attack_map: list[LiveAttackMapEntry] = []
    reasons: list[str] = []
    proposed_http_specs: list[dict[str, Any]] = []
    tool_calls: list[ToolCallRequest] = []


def live_recon_active(*, authorized: bool, target_url: str | None) -> bool:
    """Fail-closed gate: live recon runs only when authorized AND a target exists.

    Mirrors ``dynamic_validation_active`` (Phase 1): opt-in, fail-closed. Any
    falsy target URL or missing authorization means the stage is a no-op and no
    live traffic is ever proposed.
    """
    return bool(authorized and target_url)


def live_recon_impl(
    *,
    architecture: ArchitectureDoc,
    repo_path: str,
    client: Any,
    authorized: bool,
    max_iterations: int = 20,
    budget_spec: BudgetSpec | None = None,
    cost_per_iteration: float = 0.0,
    provider_policy: ProviderPolicy | None = None,
    event_sink: Any | None = None,
    turn_timeout_seconds: int = 120,
    limiter: Any | None = None,
    target_summary: str | None = None,
    allowed_hosts: list[str] | tuple[str, ...] | None = None,
    scope_exclusions: list[Any] | None = None,
    auth_profile_set: Any | None = None,
    scan_id: str | None = None,
    artifact_root: str | None = None,
) -> LiveReconResponse:
    """Core live-recon implementation — callable from the activity and tests.

    Fail-closed: when ``authorized`` is false (or no target), returns an empty
    ``LiveReconResponse`` WITHOUT running the loop — no invocation, no proposed
    egress, no traffic. When authorized, the agent reads the recon architecture
    and proposes ``http_request`` probes; the driver dispatches them (the sole
    egress). The ``allowed_hosts`` / ``scope_exclusions`` / ``auth_profile_set``
    arguments are threaded into the ToolRunner so ADR-017's fail-closed safety
    layers apply to any tool call the agent attempts inside the loop.
    """
    if not live_recon_active(authorized=authorized, target_url=target_summary):
        return LiveReconResponse(reasons=["live recon inactive: not authorized or no target"])

    if budget_spec is None:
        budget_spec = BudgetSpec()

    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="live_recon",
        registry=load_registry(),
        scope_exclusions=scope_exclusions,
        allowed_hosts=allowed_hosts,
        auth_profile_set=auth_profile_set,
    )

    registry = get_registry()
    entry_points = [
        {"repo": ep.repo, "file": ep.file, "function": ep.function, "kind": ep.kind}
        for ep in architecture.entry_points
    ]
    variables: dict[str, Any] = {
        "repo_type": architecture.repo_type,
        "primary_language": architecture.primary_language,
        "attack_surface_summary": architecture.attack_surface_summary,
        "entry_points_json": json.dumps(entry_points, separators=(",", ":")),
        "target_summary": target_summary,
    }
    prompt = build_prompt(
        registry=registry,
        role="live_recon",
        name="live_recon",
        version="1.0.0",
        variables=variables,
    )

    _, system_prompt = strip_provenance_header(prompt.messages[0].content)
    initial_message = prompt.messages[1].content

    result = run_agent_loop(
        client=client,
        role="live_recon",
        agent_kind="live_recon",
        system_prompt=system_prompt,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=LiveReconResponse,
        max_iterations=max_iterations,
        cost_per_iteration=cost_per_iteration,
        provider_policy=provider_policy,
        event_sink=event_sink,
        prompt_provenance=PromptProvenance.from_rendered(prompt),
        scan_id=scan_id,
        turn_timeout_seconds=turn_timeout_seconds,
        limiter=limiter,
    )

    if artifact_root is not None:
        persist_seed_prompt(
            artifact_root,
            rendered_messages=prompt.messages,
            invocations=client.invocations,
        )

    if result.final_answer and isinstance(result.final_answer, LiveReconResponse):
        return result.final_answer

    return LiveReconResponse(reasons=["loop ended without final answer"])


@activity.defn(name="live-recon")
def live_recon_activity(
    architecture: ArchitectureDoc | dict[str, Any],
    repo_path: str,
    authorized: bool,
    panel_json: str | None = None,
    budget_cap_usd: float | None = None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    scan_id: str | None = None,
    target_summary: str | None = None,
    allowed_hosts: list[str] | tuple[str, ...] | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    """Temporal activity: agentic live attack-map construction for a target.

    Returns a ``LiveReconResponse`` dict (JSON-serialisable at the Temporal
    boundary). The response carries ``proposed_http_specs`` for the driver to
    dispatch via the ``http-request`` activity (the sole egress).
    """
    stop_heartbeat = threading.Event()
    _ctx = contextvars.copy_context()

    def _heartbeat_loop() -> None:
        while not stop_heartbeat.wait(timeout=30):
            with suppress(Exception):
                _ctx.run(activity.heartbeat)

    heartbeat_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
    heartbeat_thread.start()

    try:
        return _live_recon_activity_impl(
            architecture,
            repo_path,
            authorized,
            panel_json,
            budget_cap_usd,
            db_path,
            max_iterations,
            scan_seed,
            scan_id,
            target_summary,
            allowed_hosts,
            artifact_root,
        )
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)


def _live_recon_activity_impl(
    architecture: ArchitectureDoc | dict[str, Any],
    repo_path: str,
    authorized: bool,
    panel_json: str | None,
    budget_cap_usd: float | None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    scan_id: str | None = None,
    target_summary: str | None = None,
    allowed_hosts: list[str] | tuple[str, ...] | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    if isinstance(architecture, dict):
        architecture = ArchitectureDoc.model_validate(architecture)

    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    if panel_json is not None:
        role_cfg = RoleConfig.model_validate_json(panel_json)
    else:
        role_cfg = DEFAULT_PANEL.get("live_recon", DEFAULT_PANEL["recon"])

    if role_cfg.provider == Provider.MOCK:
        client: Any = MockModelClient(default=LiveReconResponse())
        policy: ProviderPolicy | None = None
        limiter: Any | None = None
    else:
        client = build_model_client(role_cfg.provider, seed=scan_seed)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)
        limiter = get_limiter(role_cfg.provider.value, "live_recon", role_cfg.rpm)

    result = live_recon_impl(
        architecture=architecture,
        repo_path=repo_path,
        client=client,
        authorized=authorized,
        max_iterations=max_iterations,
        budget_spec=budget_spec,
        provider_policy=policy,
        event_sink=make_event_sink(db_path, scan_id) if scan_id else None,
        turn_timeout_seconds=role_cfg.turn_timeout_seconds,
        limiter=limiter,
        target_summary=target_summary,
        allowed_hosts=allowed_hosts,
        scan_id=scan_id,
        artifact_root=artifact_root,
    )

    persist_model_invocations(db_path, scan_id or "", client)

    return result.model_dump(mode="json")
