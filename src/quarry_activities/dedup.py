"""Deduplicate activity — deterministic clustering + agentic merge.

Algorithm (from week-13.md):
1. Group CandidateFindings by root_cause_key.
   - Clusters of size 1 are kept unchanged — no model call (deterministic).
   - Clusters of size 2–5: agent receives cluster fingerprints and reasons about
     semantic equivalence. Outputs keep_all / keep_first / keep_by_index.
   - Clusters of size >5: truncate to first 5 by discovery order, log a warning.
2. Pure set operations (exact root_cause_key match) remain deterministic.
   Only the "are these the same root cause?" judgment for ambiguous clusters
   is delegated to the agent.

Findings with root_cause_key=None are each treated as their own singleton
(None is not equal to None for grouping purposes).
"""

from __future__ import annotations

import contextvars
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from temporalio import activity

from quarry.panel_config import DEFAULT_PANEL, RoleConfig
from quarry.schemas import CandidateFinding, Provider
from quarry_models.factory import build_model_client
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.types import BudgetSpec, ProviderPolicy
from quarry_prompts import get_registry
from quarry_tools.runner import ToolRunner

_MAX_CLUSTER_SIZE = 5


class _DedupeResponse(BaseModel):
    """Model output schema for the dedup agent loop."""

    decision: str = "keep_all"  # keep_all | keep_first | keep_by_index
    keep_indices: list[int] = []
    tool_calls: list[ToolCallRequest] = []


def _apply_decision(cluster: list[CandidateFinding], response: _DedupeResponse) -> list[CandidateFinding]:
    """Apply the agent's dedup decision to a cluster of findings."""
    decision = response.decision.lower().strip()

    if decision == "keep_all":
        return list(cluster)
    elif decision == "keep_first":
        return [cluster[0]]
    elif decision == "keep_by_index":
        result: list[CandidateFinding] = []
        for idx in response.keep_indices:
            if 0 <= idx < len(cluster):
                result.append(cluster[idx])
        return result if result else [cluster[0]]  # fallback to first if indices invalid
    else:
        # Unknown decision → keep all (permissive default)
        return list(cluster)


def _dedup_impl(
    *,
    candidates: list[CandidateFinding],
    client: Any,
    max_iterations: int = 4,
    budget_spec: BudgetSpec | None = None,
    cost_per_iteration: float = 0.0,
    repo_path: str = "",
    scan_log: list[str] | None = None,
    provider_policy: ProviderPolicy | None = None,
) -> list[CandidateFinding]:
    """Core dedup implementation — callable from the activity and from tests.

    Groups by root_cause_key; None keys each get their own singleton bucket
    (None is not a valid grouping key — each null-key finding stands alone).
    """
    from quarry_tools.registry import load_registry  # noqa: PLC0415

    if budget_spec is None:
        budget_spec = BudgetSpec()

    # --- Step 1: Group by root_cause_key --------------------------------
    # Findings without a root_cause_key each go into their own singleton.
    keyed: dict[str, list[CandidateFinding]] = {}
    singletons: list[CandidateFinding] = []

    for finding in candidates:
        if not finding.root_cause_key:
            singletons.append(finding)
        else:
            keyed.setdefault(finding.root_cause_key, []).append(finding)

    result: list[CandidateFinding] = list(singletons)  # null-key findings pass through

    # --- Step 2: Process each keyed cluster ----------------------------
    runner = ToolRunner(
        repo_root=Path(repo_path) if repo_path else Path("."),
        role="gapfill",  # reuses read toolset; no code execution
        registry=load_registry(),
        budget_spec=budget_spec,
    )

    registry = get_registry()

    for key, cluster in keyed.items():
        if len(cluster) == 1:
            # Singleton cluster: keep unchanged, no model call
            result.append(cluster[0])
            continue

        # Warn and truncate clusters larger than _MAX_CLUSTER_SIZE
        if len(cluster) > _MAX_CLUSTER_SIZE:
            if scan_log is not None:
                scan_log.append(
                    f"dedup: cluster key={key!r} has {len(cluster)} findings; "
                    f"truncating to first {_MAX_CLUSTER_SIZE} by discovery order."
                )
            cluster = cluster[:_MAX_CLUSTER_SIZE]

        # Build a minimal description of the cluster for the agent
        fingerprint_lines = "\n".join(
            f"  [{i}] id={f.id} vuln_class={f.vuln_class.value} "
            f"affected={f.affected_component or '(unknown)'} title={f.title!r}"
            for i, f in enumerate(cluster)
        )

        # Use a minimal prompt since no full-featured gapfill template is needed
        system_prompt = (
            "You are a security deduplication agent. You receive a cluster of security "
            "findings that share the same root cause key. Decide which to keep.\n"
            "Rules:\n"
            "- 'keep_all': all findings are distinct enough to keep.\n"
            "- 'keep_first': the first finding (index 0) is representative; drop the rest.\n"
            "- 'keep_by_index': keep only the findings at the listed indices.\n"
            "Return JSON with 'decision' and (if keep_by_index) 'keep_indices'."
        )
        initial_message = (
            f"These {len(cluster)} findings share root_cause_key={key!r}. "
            f"Are they duplicates of each other?\n\n{fingerprint_lines}\n\n"
            "Return your decision."
        )

        loop_result = run_agent_loop(
            client=client,
            role="gapfill",
            agent_kind="gapfill",
            system_prompt=system_prompt,
            initial_user_message=initial_message,
            runner=runner,
            budget_spec=budget_spec,
            response_model=_DedupeResponse,
            max_iterations=max_iterations,
            cost_per_iteration=cost_per_iteration,
            provider_policy=provider_policy,
        )

        if loop_result.final_answer and isinstance(loop_result.final_answer, _DedupeResponse):
            kept = _apply_decision(cluster, loop_result.final_answer)
        else:
            # Loop didn't return a clean answer → keep all (permissive default)
            kept = list(cluster)

        result.extend(kept)

    return result


@activity.defn(name="deduplicate-findings")
def deduplicate_activity(
    candidates: list[dict[str, Any]] | None = None,
    repo_path: str = "",
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
) -> list[dict[str, Any]]:
    """Temporal activity: deduplicate CandidateFindings by root_cause_key.

    Returns a list of CandidateFinding dicts (JSON-serialisable at the Temporal boundary).
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
        return _deduplicate_activity_impl(candidates, repo_path, budget_cap_usd, panel_json)
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)


def _deduplicate_activity_impl(
    candidates: list[dict[str, Any]] | None,
    repo_path: str,
    budget_cap_usd: float | None,
    panel_json: str | None,
) -> list[dict[str, Any]]:
    parsed: list[CandidateFinding] = []
    if candidates:
        for c in candidates:
            if isinstance(c, dict):
                parsed.append(CandidateFinding.model_validate(c))
            elif isinstance(c, CandidateFinding):
                parsed.append(c)

    from quarry_models.mock_client import MockModelClient  # noqa: PLC0415

    role_cfg = (
        RoleConfig.model_validate_json(panel_json)
        if panel_json is not None
        else DEFAULT_PANEL["gapfill"]  # dedup reuses the gapfill toolset
    )

    if role_cfg.provider == Provider.MOCK:
        client: Any = MockModelClient(default=_DedupeResponse())
        policy: ProviderPolicy | None = None
    else:
        client = build_model_client(role_cfg.provider)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)

    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)
    scan_log: list[str] = []

    result = _dedup_impl(
        candidates=parsed,
        client=client,
        budget_spec=budget_spec,
        repo_path=repo_path,
        scan_log=scan_log,
        provider_policy=policy,
    )

    return [f.model_dump(mode="json") for f in result]
