"""Dynamic-validation activity — agentic live corroboration for a CandidateFinding.

The dynamic-validation agent takes ONE validated code-level candidate and a live
target and proposes a single, minimal ``http_request`` that would corroborate
(or fail to corroborate) the hypothesis against the running app.  It NEVER opens
a socket inside the loop — the http tool returns a dispatch payload only, and the
WORKFLOW performs the single allow-listed egress (ADR-017).

Agent proposes → workflow dispatches → live verdict mapped by a pure helper
(``quarry_workflows.dynamic_validate_stage.resolve_live_verdict``).  This
preserves loop-in-activity determinism and the Temporal execution model, and
keeps the sole egress path in ``http_request_activity``.
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
from quarry.schemas import (
    CandidateFinding,
    Provider,
)
from quarry_activities.event_sink import make_event_sink
from quarry_activities.model_cost import persist_model_invocations
from quarry_artifacts.store import persist_seed_prompt
from quarry_models.factory import build_model_client
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec, PromptProvenance, ProviderPolicy
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_prompts.registry import TemplateNotFoundError
from quarry_tools.registry import load_registry
from quarry_tools.runner import ToolRunner


class DynamicValidateResponse(BaseModel):
    """Model output schema for the dynamic-validation agent loop.

    The agent populates ``proposed_http_specs`` with the single live probe it
    wants the workflow to dispatch, along with its own preliminary ``verdict``.
    The authoritative live verdict is produced by ``resolve_live_verdict`` once
    the workflow has dispatched the probe and captured the real response.
    """

    verdict: str = "inconclusive"
    # "corroborated" | "not_corroborated" | "inconclusive"
    reasons: list[str] = []
    proposed_http_specs: list[dict[str, Any]] = []
    tool_calls: list[ToolCallRequest] = []


def dynamic_validate_impl(
    *,
    finding: CandidateFinding,
    repo_path: str,
    client: Any,
    max_iterations: int = 20,
    budget_spec: BudgetSpec | None = None,
    cost_per_iteration: float = 0.0,
    provider_policy: ProviderPolicy | None = None,
    event_sink: Any | None = None,
    turn_timeout_seconds: int = 120,
    target_summary: str | None = None,
    allowed_hosts: list[str] | tuple[str, ...] | None = None,
    scope_exclusions: list[Any] | None = None,
    auth_profile_set: Any | None = None,
    prior_attempts: list[dict[str, Any]] | None = None,
    artifact_root: str | None = None,
) -> DynamicValidateResponse:
    """Core dynamic-validation implementation — callable from the activity and tests.

    The agent reads the cited source and proposes ONE ``http_request`` against the
    live target.  It never executes the probe; the workflow dispatches it via the
    ``http-request`` activity (the sole egress) with ``maximum_attempts=1``.

    The ``allowed_hosts`` / ``scope_exclusions`` / ``auth_profile_set`` arguments
    are threaded into the ToolRunner so ADR-017's fail-closed safety layers apply
    to any tool call the agent attempts inside the loop.
    """
    if budget_spec is None:
        budget_spec = BudgetSpec()

    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="dynamic_validate",
        registry=load_registry(),
        budget_spec=budget_spec,
        scope_exclusions=scope_exclusions,
        allowed_hosts=allowed_hosts,
        auth_profile_set=auth_profile_set,
    )

    registry = get_registry()
    variables: dict[str, Any] = {
        "vuln_class": finding.vuln_class.value,
        "title": finding.title,
        "affected_component": finding.affected_component or "",
        "hypothesis": finding.hypothesis,
        "target_summary": target_summary,
        "prior_attempts_json": (
            json.dumps(prior_attempts, separators=(",", ":")) if prior_attempts else None
        ),
        "evidence_chunks": [],
    }
    # Prefer the per-class template (prompts/dynamic_validate/<vuln_class>.1.0.0.j2);
    # fall back to the generic dynamic_validate template for classes without one.
    try:
        prompt = build_prompt(
            registry=registry,
            role="dynamic_validate",
            name=finding.vuln_class.value,
            version="1.0.0",
            variables=variables,
        )
    except TemplateNotFoundError:
        prompt = build_prompt(
            registry=registry,
            role="dynamic_validate",
            name="dynamic_validate",
            version="1.0.0",
            variables=variables,
        )

    _, system_prompt = strip_provenance_header(prompt.messages[0].content)
    initial_message = prompt.messages[1].content

    result = run_agent_loop(
        client=client,
        role="dynamic_validate",
        agent_kind="dynamic_validate",
        system_prompt=system_prompt,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=DynamicValidateResponse,
        max_iterations=max_iterations,
        cost_per_iteration=cost_per_iteration,
        provider_policy=provider_policy,
        event_sink=event_sink,
        prompt_provenance=PromptProvenance.from_rendered(prompt),
        scan_id=finding.scan_id,
        turn_timeout_seconds=turn_timeout_seconds,
    )

    if artifact_root is not None:
        persist_seed_prompt(
            artifact_root,
            rendered_messages=prompt.messages,
            invocations=client.invocations,
        )

    if result.final_answer and isinstance(result.final_answer, DynamicValidateResponse):
        return result.final_answer

    return DynamicValidateResponse(
        verdict="inconclusive", reasons=["loop ended without final answer"]
    )


@activity.defn(name="dynamic-validate-finding")
def dynamic_validate_activity(
    finding: CandidateFinding | dict[str, Any],
    repo_path: str,
    panel: dict[str, Any] | None = None,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    target_summary: str | None = None,
    allowed_hosts: list[str] | tuple[str, ...] | None = None,
    prior_attempts: list[dict[str, Any]] | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    """Temporal activity: agentic live corroboration for a single finding.

    Returns a DynamicValidateResponse dict (JSON-serialisable at the Temporal
    boundary).  The response carries ``proposed_http_specs`` for the workflow to
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
        return _dynamic_validate_activity_impl(
            finding,
            repo_path,
            panel,
            budget_cap_usd,
            panel_json,
            db_path,
            max_iterations,
            scan_seed,
            target_summary,
            allowed_hosts,
            prior_attempts,
            artifact_root,
        )
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)


def _dynamic_validate_activity_impl(
    finding: CandidateFinding | dict[str, Any],
    repo_path: str,
    panel: dict[str, Any] | None,
    budget_cap_usd: float | None,
    panel_json: str | None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    target_summary: str | None = None,
    allowed_hosts: list[str] | tuple[str, ...] | None = None,
    prior_attempts: list[dict[str, Any]] | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    if isinstance(finding, dict):
        finding = CandidateFinding.model_validate(finding)

    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    if panel_json is not None:
        role_cfg = RoleConfig.model_validate_json(panel_json)
    else:
        role_cfg = DEFAULT_PANEL.get("dynamic_validate", DEFAULT_PANEL["validate"])

    if role_cfg.provider == Provider.MOCK:
        client: Any = MockModelClient(default=DynamicValidateResponse())
        policy: ProviderPolicy | None = None
    else:
        client = build_model_client(role_cfg.provider, seed=scan_seed)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)

    result = dynamic_validate_impl(
        finding=finding,
        repo_path=repo_path,
        client=client,
        max_iterations=max_iterations,
        budget_spec=budget_spec,
        provider_policy=policy,
        event_sink=make_event_sink(db_path, finding.scan_id),
        turn_timeout_seconds=role_cfg.turn_timeout_seconds,
        target_summary=target_summary,
        allowed_hosts=allowed_hosts,
        prior_attempts=prior_attempts,
        artifact_root=artifact_root,
    )

    persist_model_invocations(db_path, finding.scan_id, client)

    return result.model_dump(mode="json")
