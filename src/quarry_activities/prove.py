"""Prove activity — agentic proof-of-concept generation for CandidateFinding.

The prove agent proposes sandbox exec specs and/or HTTP probe specs based on
static analysis of the finding.  It NEVER performs live I/O inside the loop —
all proposed specs are returned to the workflow for dispatching via
sandbox-exec / http-request activities (Phase 6).

Agent proposes → workflow dispatches → proof artifact produced.
This preserves loop-in-activity determinism and the Temporal execution model.
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
from quarry_models.rate_limit import get_limiter
from quarry_models.types import BudgetSpec, PromptProvenance, ProviderPolicy
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_tools.registry import load_registry
from quarry_tools.runner import ToolRunner


class ProveResponse(BaseModel):
    """Model output schema for the prove agent loop.

    The agent populates proposed_exec_specs and proposed_http_specs in its
    final response (empty tool_calls).  The workflow then dispatches those
    specs via sandbox-exec / http-request activities with maximum_attempts=1.
    """

    verdict: str = "inconclusive"
    # "proved" | "not_proved" | "inconclusive" | "needs_manual_review"
    # Python enforces needs_manual_review via prove_outcome_from_captures;
    # the model never emits it directly.
    proposed_exec_specs: list[dict[str, Any]] = []
    proposed_http_specs: list[dict[str, Any]] = []
    reasons: list[str] = []
    tool_calls: list[ToolCallRequest] = []


def prove_impl(
    *,
    finding: CandidateFinding,
    repo_path: str,
    panel: dict[str, Any],
    client: Any,
    max_iterations: int = 20,
    budget_spec: BudgetSpec | None = None,
    cost_per_iteration: float = 0.0,
    provider_policy: ProviderPolicy | None = None,
    event_sink: Any | None = None,
    turn_timeout_seconds: int = 120,
    limiter: Any | None = None,
    prior_attempts: list[dict[str, Any]] | None = None,
    artifact_root: str | None = None,
) -> ProveResponse:
    """Core prove implementation — callable from the activity and from tests.

    The agent reads source code and proposes sandbox exec specs or HTTP probe
    specs.  It never executes them; the workflow dispatches them (Phase 6).

    Args:
        prior_attempts: Optional list of prior attempt records built by
            build_prior_attempt_record().  When provided, a deterministic
            feedback line is appended to the initial user message so the
            agent can refine its approach.  Default None (first attempt).
    """
    if budget_spec is None:
        budget_spec = BudgetSpec()

    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="prove",
        registry=load_registry(),
    )

    registry = get_registry()
    prompt = build_prompt(
        registry=registry,
        role="prove",
        name="prove",
        version="1.0.0",
        variables={
            "vuln_class": finding.vuln_class.value,
            "file": finding.affected_component or "",
            "line_start": None,
            "line_end": None,
            "description": finding.hypothesis,
            "affected_code_snippet": None,
            "prior_attempts_json": (
                json.dumps(prior_attempts, separators=(",", ":")) if prior_attempts else None
            ),
        },
    )

    _, system_prompt = strip_provenance_header(prompt.messages[0].content)
    initial_message = prompt.messages[1].content

    result = run_agent_loop(
        client=client,
        role="prove",
        agent_kind="prove",
        system_prompt=system_prompt,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=ProveResponse,
        max_iterations=max_iterations,
        cost_per_iteration=cost_per_iteration,
        provider_policy=provider_policy,
        event_sink=event_sink,
        prompt_provenance=PromptProvenance.from_rendered(prompt),
        scan_id=finding.scan_id,
        turn_timeout_seconds=turn_timeout_seconds,
        limiter=limiter,
    )

    if artifact_root is not None:
        persist_seed_prompt(
            artifact_root,
            rendered_messages=prompt.messages,
            invocations=client.invocations,
        )

    if result.final_answer and isinstance(result.final_answer, ProveResponse):
        return result.final_answer

    return ProveResponse(verdict="inconclusive", reasons=["loop ended without final answer"])


@activity.defn(name="prove-finding")
def prove_activity(
    finding: CandidateFinding | dict[str, Any],
    repo_path: str,
    panel: dict[str, Any] | None = None,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    prior_attempts: list[dict[str, Any]] | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    """Temporal activity: agentic proof-of-concept generation for a single finding.

    Returns a ProveResponse dict (JSON-serialisable at the Temporal boundary).
    The response includes proposed_exec_specs and proposed_http_specs for the
    workflow to dispatch via sandbox-exec / http-request activities.

    Args:
        prior_attempts: Optional list of prior attempt records (from
            build_prior_attempt_record) carrying verdict+reasons from earlier
            attempts.  Passed through to prove_impl so the agent can adapt.
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
        return _prove_activity_impl(
            finding,
            repo_path,
            panel,
            budget_cap_usd,
            panel_json,
            db_path,
            max_iterations,
            scan_seed,
            prior_attempts,
            artifact_root,
        )
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)


def _prove_activity_impl(
    finding: CandidateFinding | dict[str, Any],
    repo_path: str,
    panel: dict[str, Any] | None,
    budget_cap_usd: float | None,
    panel_json: str | None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    prior_attempts: list[dict[str, Any]] | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    if isinstance(finding, dict):
        finding = CandidateFinding.model_validate(finding)

    active_panel: dict[str, Any] = panel if panel is not None else dict(DEFAULT_PANEL)
    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    if panel_json is not None:
        role_cfg = RoleConfig.model_validate_json(panel_json)
    else:
        role_cfg = DEFAULT_PANEL.get("prove", DEFAULT_PANEL["validate"])

    if role_cfg.provider == Provider.MOCK:
        client: Any = MockModelClient(default=ProveResponse())
        policy: ProviderPolicy | None = None
        limiter: Any | None = None
    else:
        client = build_model_client(role_cfg.provider, seed=scan_seed)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)
        limiter = get_limiter(role_cfg.provider.value, "prove", role_cfg.rpm)

    result = prove_impl(
        finding=finding,
        repo_path=repo_path,
        panel=active_panel,
        client=client,
        max_iterations=max_iterations,
        budget_spec=budget_spec,
        provider_policy=policy,
        event_sink=make_event_sink(db_path, finding.scan_id),
        turn_timeout_seconds=role_cfg.turn_timeout_seconds,
        limiter=limiter,
        prior_attempts=prior_attempts,
        artifact_root=artifact_root,
    )

    persist_model_invocations(db_path, finding.scan_id, client)

    return result.model_dump(mode="json")
