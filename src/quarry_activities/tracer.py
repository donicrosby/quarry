"""Tracer activity — reachability verdict for CandidateFinding.

The tracer agent reasons over a CallGraph to determine whether attacker-controlled
input at an entry point can reach a vulnerable sink.  It produces one of three
verdicts: ``reachable``, ``not_reachable``, or ``indeterminate``.

Safety rule — the C/C++ indeterminate override:
  If ``call_graph.index_kind`` is in ``UNRESOLVED_GRAPH_KINDS`` AND the finding
  language is in ``UNRESOLVED_GRAPH_LANGUAGES`` AND the model emits
  ``not_reachable``, the verdict is FORCED to ``indeterminate`` in Python code.
  This is an explicit conditional branch, not a prompt instruction.  The model
  cannot bypass it.  See ADR-017.

Severity re-ranking:
  A ``not_reachable`` verdict downgrades the finding's severity by one level
  (floor = ``low``).  Findings in ``SEVERITY_EXEMPT_VULN_CLASSES`` (i.e. secrets)
  are exempt — their severity is never changed by a tracer verdict.
"""

from __future__ import annotations

import contextvars
import json
import threading
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from temporalio import activity

from quarry.panel_config import DEFAULT_PANEL, RoleConfig
from quarry.schemas import (
    CallGraph,
    CandidateFinding,
    Provider,
    ReachabilityVerdict,
    Severity,
    Trace,
    VulnerabilityClass,
)
from quarry_activities.event_sink import make_event_sink
from quarry_activities.model_cost import persist_model_invocations
from quarry_artifacts.store import persist_seed_prompt
from quarry_models.factory import build_model_client
from quarry_models.loop import run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec, PromptProvenance, ProviderPolicy
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_tools.registry import load_registry
from quarry_tools.runner import ToolRunner

# ---------------------------------------------------------------------------
# Safety constants — explicit named sets, not inline literals
# ---------------------------------------------------------------------------

# Call-graph index kinds whose edges may be incomplete, making "not_reachable"
# an unreliable verdict for C/C++ code (ast_grep can miss indirect calls).
UNRESOLVED_GRAPH_KINDS: frozenset[str] = frozenset({"ast_grep"})

# Languages where an unresolved graph must force "indeterminate".
# C and C++ use ast_grep for call graphs; SCIP is not supported there.
UNRESOLVED_GRAPH_LANGUAGES: frozenset[str] = frozenset({"c", "cpp", "c++"})

# Findings whose severity is NEVER changed by a reachability verdict.
# Secrets are always critical regardless of reachability.
SEVERITY_EXEMPT_VULN_CLASSES: frozenset[VulnerabilityClass] = frozenset(
    {VulnerabilityClass.SECRETS}
)

# Ordered severity ladder used for downgrade.  INFO is not on the ladder —
# it falls through unchanged (it is not a severity the tracer should demote).
_SEVERITY_LADDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)

# ---------------------------------------------------------------------------
# TraceResponse — model output schema
# ---------------------------------------------------------------------------


class TraceResponse(BaseModel):
    """Model output schema for the tracer agent loop.

    The agent emits a single final response (empty tool_calls) with its verdict
    and reasoning.  No live execution is performed in the loop.
    """

    verdict: str = "indeterminate"  # "reachable" | "not_reachable" | "indeterminate"
    reasons: list[str] = []


# ---------------------------------------------------------------------------
# Public helper — severity downgrade
# ---------------------------------------------------------------------------


def downgrade_severity(severity: Severity) -> Severity:
    """Return the next-lower severity, floored at ``low``.

    ``info`` is not on the tracer's demotion ladder and is returned unchanged.
    This matches the policy: tracer verdicts do not promote or re-label INFO.
    """
    try:
        idx = _SEVERITY_LADDER.index(severity)
    except ValueError:
        # Not on the ladder (e.g. INFO) — return unchanged.
        return severity
    # Floor: cannot go below the last element (LOW).
    new_idx = min(idx + 1, len(_SEVERITY_LADDER) - 1)
    return _SEVERITY_LADDER[new_idx]


# ---------------------------------------------------------------------------
# Override rule — C/C++ indeterminate
# ---------------------------------------------------------------------------


def _apply_cpp_indeterminate_override(
    model_verdict: str,
    *,
    call_graph: CallGraph,
    finding: CandidateFinding,
) -> str:
    """Force ``indeterminate`` when the graph is unresolved for C/C++ code.

    This is an explicit conditional branch — the model cannot suppress it.
    See module docstring for rationale.
    """
    language: str = (finding.metadata.get("language") or "").lower().strip()

    if (
        call_graph.index_kind in UNRESOLVED_GRAPH_KINDS
        and language in UNRESOLVED_GRAPH_LANGUAGES
        and model_verdict == "not_reachable"
    ):
        return "indeterminate"
    return model_verdict


# ---------------------------------------------------------------------------
# Core implementation
# ---------------------------------------------------------------------------


def tracer_impl(
    *,
    finding: CandidateFinding,
    call_graph: CallGraph,
    repo_path: str,
    panel: dict[str, Any],
    client: Any,
    max_iterations: int = 10,
    budget_spec: BudgetSpec | None = None,
    cost_per_iteration: float = 0.0,
    provider_policy: ProviderPolicy | None = None,
    event_sink: Any | None = None,
    turn_timeout_seconds: int = 120,
    artifact_root: str | None = None,
) -> Trace:
    """Core tracer implementation — callable from the activity and from tests.

    Runs the tracer agent loop, applies the C/C++ override rule, applies
    severity re-ranking (in-place on *finding*), and returns a :class:`Trace`.
    """
    if budget_spec is None:
        budget_spec = BudgetSpec()

    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="trace",
        registry=load_registry(),
        budget_spec=budget_spec,
    )

    registry = get_registry()
    edges_json = json.dumps(
        [
            {
                "caller": f"{e.caller_file}:{e.caller_function}",
                "callee": f"{e.callee_file}:{e.callee_function}",
            }
            for e in call_graph.edges
        ],
        indent=2,
    )

    entry_points_data = [
        {
            "kind": ep.kind,
            "repo": ep.repo,
            "file": ep.file,
            "function": ep.function,
        }
        for ep in call_graph.entry_points
    ]

    prompt = build_prompt(
        registry=registry,
        role="trace",
        name="trace",
        version="1.0.0",
        variables={
            "vuln_class": finding.vuln_class.value,
            "file": finding.affected_component or "",
            "line_start": None,
            "line_end": None,
            "description": finding.hypothesis,
            "entry_points": entry_points_data,
            "edges_json": edges_json if call_graph.edges else "",
            "edge_count": len(call_graph.edges),
            "index_kind": call_graph.index_kind,
        },
    )

    _, system_prompt = strip_provenance_header(prompt.messages[0].content)
    initial_message = prompt.messages[1].content

    result = run_agent_loop(
        client=client,
        role="trace",
        agent_kind="trace",
        system_prompt=system_prompt,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=TraceResponse,
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

    if result.final_answer and isinstance(result.final_answer, TraceResponse):
        raw_verdict = result.final_answer.verdict
        reasons = result.final_answer.reasons
    else:
        raw_verdict = "indeterminate"
        reasons = ["loop ended without final answer"]

    # ── C/C++ override rule (explicit branch) ───────────────────────────────
    final_verdict = _apply_cpp_indeterminate_override(
        raw_verdict,
        call_graph=call_graph,
        finding=finding,
    )

    # ── Severity re-ranking (in-place) ──────────────────────────────────────
    if final_verdict == "not_reachable" and finding.vuln_class not in SEVERITY_EXEMPT_VULN_CLASSES:
        finding.severity = downgrade_severity(finding.severity)

    return Trace(
        id=str(uuid.uuid4()),
        scan_id=finding.scan_id,
        finding_id=finding.id,
        reachable=ReachabilityVerdict(final_verdict),
        entry_points=call_graph.entry_points,
        trace_notes="; ".join(reasons) if reasons else None,
    )


# ---------------------------------------------------------------------------
# Temporal activity (sync — runs in thread-pool)
# ---------------------------------------------------------------------------


@activity.defn(name="tracer-finding")
def tracer_activity(
    finding: CandidateFinding | dict[str, Any],
    call_graph: CallGraph | dict[str, Any],
    repo_path: str,
    panel: dict[str, Any] | None = None,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 10,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    """Temporal activity: reachability verdict for a single finding.

    Returns a :class:`Trace` dict (JSON-serialisable at the Temporal boundary).
    Registered as ``tracer-finding`` in quarry_worker/main.py and
    quarry_server/app.py (dual-worker rule).
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
        return _tracer_activity_impl(
            finding,
            call_graph,
            repo_path,
            panel,
            budget_cap_usd,
            panel_json,
            db_path,
            max_iterations,
            scan_seed,
            artifact_root,
        )
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)


def _tracer_activity_impl(
    finding: CandidateFinding | dict[str, Any],
    call_graph: CallGraph | dict[str, Any],
    repo_path: str,
    panel: dict[str, Any] | None,
    budget_cap_usd: float | None,
    panel_json: str | None,
    db_path: str | None = None,
    max_iterations: int = 10,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    if isinstance(finding, dict):
        finding = CandidateFinding.model_validate(finding)
    if isinstance(call_graph, dict):
        call_graph = CallGraph.model_validate(call_graph)

    active_panel: dict[str, Any] = panel if panel is not None else dict(DEFAULT_PANEL)
    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    if panel_json is not None:
        role_cfg = RoleConfig.model_validate_json(panel_json)
    else:
        role_cfg = DEFAULT_PANEL.get("trace", DEFAULT_PANEL["validate"])

    if role_cfg.provider == Provider.MOCK:
        client: Any = MockModelClient(default=TraceResponse())
        policy: ProviderPolicy | None = None
    else:
        client = build_model_client(role_cfg.provider, seed=scan_seed)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)

    trace = tracer_impl(
        finding=finding,
        call_graph=call_graph,
        repo_path=repo_path,
        panel=active_panel,
        client=client,
        max_iterations=max_iterations,
        budget_spec=budget_spec,
        provider_policy=policy,
        event_sink=make_event_sink(db_path, finding.scan_id),
        turn_timeout_seconds=role_cfg.turn_timeout_seconds,
        artifact_root=artifact_root,
    )

    persist_model_invocations(db_path, finding.scan_id, client)

    return trace.model_dump(mode="json")
