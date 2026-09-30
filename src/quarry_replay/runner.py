"""Replay runner: invoke ONE agentic activity directly under a resolved panel.

The runner is the bridge between a stage's resolved inputs and its activity
entry point. Guarantees (prompt-replay-harness spec):

- Direct activity call — no Temporal workflow, no task queue.
- Model routing parity — the panel is resolved through the same
  ``load_quarry_config`` + ``resolve_panel`` path as a real scan (resolvers).
- Read-only — the scan's persisted state is never mutated: the replay passes
  ``db_path=None`` down to the activity (no event rows, no invocation rows)
  and records model invocations OUT-OF-BAND, replay-tagged.
- Mock labeling — ``--mock`` selects the all-mock panel explicitly and the
  returned envelope's header labels the result as mock, so a mock replay can
  never be mistaken for a real one.
"""

from __future__ import annotations

import json
from typing import Any

from quarry_replay.resolvers import (
    GapfillInputs,
    HuntInputs,
    MockPanelError,
    PanelSelection,
    ProveInputs,
    ReconInputs,
    ReplayResolutionError,
    TraceInputs,
    ValidateInputs,
    config_panel_name,
    resolve_gapfill_inputs,
    resolve_hunt_inputs,
    resolve_prove_inputs,
    resolve_recon_inputs,
    resolve_trace_inputs,
    resolve_validate_inputs,
)

_STAGES = ("hunt", "gapfill", "validate", "prove", "trace", "recon")


def stage_names() -> tuple[str, ...]:
    """The supported replay stages, in CLI order."""
    return _STAGES


def tag_invocations_as_replay(
    invocations: list[dict[str, Any]],
    *,
    scan_id: str,
    panel: PanelSelection,
) -> list[dict[str, Any]]:
    """Re-tag serialised ModelInvocation dicts as replay invocations.

    A replay's model calls must be attributable as replay spend without
    polluting the scan's provenance: ``workspace_id`` becomes ``replay`` and
    ``task_name`` is stamped with a ``replay:<panel>:<role>`` prefix, with the
    structured marker in ``metadata``. Because the replay never writes to the
    scan DB, these tagged rows are what a caller persists OUT-OF-BAND (or
    discards for mock runs).
    """
    tagged: list[dict[str, Any]] = []
    for inv in invocations:
        row = dict(inv)
        row["workspace_id"] = "replay"
        row["task_name"] = f"replay:{panel.panel_name}:{panel.role}"
        metadata = row.get("metadata")
        metadata = dict(metadata) if isinstance(metadata, dict) else {}
        metadata["replay"] = True
        metadata["replay_panel"] = panel.panel_name
        metadata["replay_role"] = panel.role
        metadata["replay_scan_id"] = scan_id
        row["metadata"] = metadata
        tagged.append(row)
    return tagged


def _client_invocation_rows(client: Any) -> list[dict[str, Any]]:
    """Serialise a model client's recorded invocations (empty when absent)."""
    invocations = getattr(client, "invocations", None)
    if not invocations:
        return []
    rows: list[dict[str, Any]] = []
    for inv in invocations:
        if hasattr(inv, "model_dump"):
            rows.append(dict(inv.model_dump(mode="json")))
        elif isinstance(inv, dict):
            rows.append(dict(inv))
    return rows


def run_replay(
    *,
    stage: str,
    db_path: str,
    scan_id: str,
    repo_path: str,
    mock: bool = False,
    panel_name: str | None = None,
    artifact_root: str | None = None,
    vuln_class: str | None = None,
    finding_id: str | None = None,
    sub_index: int = 0,
    max_iterations: int | None = None,
    budget_cap_usd: float | None = None,
    allow_mock_panel: bool = True,
) -> dict[str, Any]:
    """Resolve inputs for *stage* and invoke its activity function directly.

    Returns a JSON-serialisable envelope::

        {"stage", "scan_id", "mode", "panel", "header", "invocations", "result"}

    ``mode`` is ``mock`` | ``real``; ``invocations`` are the replay-tagged
    model invocation rows (recorded out-of-band, never into the scan DB).
    """
    if stage not in _STAGES:
        msg = f"unknown stage {stage!r}; valid stages: {', '.join(_STAGES)}"
        raise ValueError(msg)

    if stage == "validate":
        inputs: Any = resolve_validate_inputs(
            db_path=db_path,
            scan_id=scan_id,
            repo_path=repo_path,
            vuln_class=vuln_class,
            panel_name=panel_name,
            allow_mock_panel=allow_mock_panel,
            mock=mock,
        )
    elif stage == "hunt":
        inputs = resolve_hunt_inputs(
            db_path=db_path,
            scan_id=scan_id,
            repo_path=repo_path,
            vuln_class=vuln_class or "secrets",
            panel_name=panel_name,
            mock=mock,
        )
    elif stage == "gapfill":
        inputs = resolve_gapfill_inputs(
            db_path=db_path,
            scan_id=scan_id,
            repo_path=repo_path,
            artifact_root=artifact_root,
            panel_name=panel_name,
            mock=mock,
        )
    elif stage == "prove":
        inputs = resolve_prove_inputs(
            db_path=db_path,
            scan_id=scan_id,
            repo_path=repo_path,
            finding_id=finding_id,
            panel_name=panel_name,
            mock=mock,
        )
    elif stage == "trace":
        inputs = resolve_trace_inputs(
            db_path=db_path,
            scan_id=scan_id,
            repo_path=repo_path,
            finding_id=finding_id,
            panel_name=panel_name,
            mock=mock,
        )
    else:
        inputs = resolve_recon_inputs(
            db_path=db_path,
            scan_id=scan_id,
            repo_path=repo_path,
            sub_index=sub_index,
            panel_name=panel_name,
            mock=mock,
        )

    panel = inputs.panel
    result, invocations = _invoke(
        stage, inputs, mock=mock, max_iterations=max_iterations, budget_cap_usd=budget_cap_usd
    )
    tagged = tag_invocations_as_replay(invocations, scan_id=scan_id, panel=panel)
    mode = "mock" if panel.is_mock else "real"
    return {
        "stage": stage,
        "scan_id": scan_id,
        "mode": mode,
        "panel": panel.panel_name,
        "header": panel.header_lines(),
        "invocations": tagged,
        "result": result,
    }


def _invoke(
    stage: str,
    inputs: Any,
    *,
    mock: bool,
    max_iterations: int | None,
    budget_cap_usd: float | None,
) -> tuple[Any, list[dict[str, Any]]]:
    """Call the stage's activity directly with the resolved inputs.

    ``db_path`` is NEVER forwarded: activities persist model invocations and
    agent events through it, and replay must not write to the scan DB (the
    read-only guarantee). Invocations are captured from the client the
    activity built (mock or real) and returned for out-of-band recording.
    """
    # The activity builds its own client internally; to capture invocations we
    # intercept the client factory once (activities only build clients here).
    captured: list[dict[str, Any]] = []

    if stage == "validate":
        from quarry_activities.validate import validate_activity

        assert isinstance(inputs, ValidateInputs)
        iterations = max_iterations if max_iterations is not None else 20
        budget = budget_cap_usd if budget_cap_usd is not None else _default_budget(mock)
        with _capture_clients(captured):
            result = validate_activity(
                inputs.candidate.model_dump(mode="json"),
                inputs.repo_path,
                panel_json=inputs.panel.role_config.model_dump_json(),
                budget_cap_usd=budget,
                max_iterations=iterations,
            )
        return result, captured

    if stage == "hunt":
        from quarry_activities.hunt import hunt_activity

        assert isinstance(inputs, HuntInputs)
        iterations = max_iterations if max_iterations is not None else 12
        budget = budget_cap_usd if budget_cap_usd is not None else _default_budget(mock)
        with _capture_clients(captured):
            result = hunt_activity(
                inputs.task,
                inputs.repo_path,
                max_iterations=iterations,
                budget_cap_usd=budget,
                panel_json=inputs.panel.role_config.model_dump_json(),
                artifact_root=artifact_root_of(inputs),
                kb_root_index_key=inputs.kb_root_index_key,
            )
        return result, captured

    if stage == "gapfill":
        from quarry_activities.gapfill import gapfill_activity

        assert isinstance(inputs, GapfillInputs)
        iterations = max_iterations if max_iterations is not None else 20
        budget = budget_cap_usd if budget_cap_usd is not None else _default_budget(mock)
        with _capture_clients(captured):
            result = gapfill_activity(
                inputs.ledger.model_dump(mode="json"),
                inputs.existing_tasks,
                None,
                inputs.repo_path,
                budget,
                inputs.panel.role_config.model_dump_json(),
                None,
                None,
                inputs.existing_findings,
                iterations,
                None,
                inputs.kb_root_index_key and artifact_root_of(inputs),
                inputs.kb_root_index_key,
            )
        return result, captured

    if stage == "prove":
        from quarry_activities.prove import prove_activity

        assert isinstance(inputs, ProveInputs)
        iterations = max_iterations if max_iterations is not None else 20
        budget = budget_cap_usd if budget_cap_usd is not None else _default_budget(mock)
        with _capture_clients(captured):
            result = prove_activity(
                inputs.candidate.model_dump(mode="json"),
                inputs.repo_path,
                panel_json=inputs.panel.role_config.model_dump_json(),
                budget_cap_usd=budget,
                max_iterations=iterations,
            )
        return result, captured

    if stage == "trace":
        from quarry_activities.tracer import tracer_activity

        assert isinstance(inputs, TraceInputs)
        iterations = max_iterations if max_iterations is not None else 10
        budget = budget_cap_usd if budget_cap_usd is not None else _default_budget(mock)
        with _capture_clients(captured):
            result = tracer_activity(
                inputs.candidate.model_dump(mode="json"),
                inputs.call_graph.model_dump(mode="json"),
                inputs.repo_path,
                panel_json=inputs.panel.role_config.model_dump_json(),
                budget_cap_usd=budget,
                max_iterations=iterations,
            )
        return result, captured

    from quarry_activities.recon_subsystem import recon_subsystem_activity

    assert isinstance(inputs, ReconInputs)
    iterations = max_iterations if max_iterations is not None else 40
    with _capture_clients(captured):
        subsystem = recon_subsystem_activity(
            inputs.assignment,
            inputs.repo_root,
            inputs.scan_id,
            budget_spec=None,
            panel_json=inputs.panel.role_config.model_dump_json(),
            max_iterations=iterations,
        )
    return _subsystem_to_dict(subsystem), captured


def _subsystem_to_dict(subsystem: Any) -> dict[str, Any]:
    if hasattr(subsystem, "model_dump"):
        return dict(subsystem.model_dump(mode="json"))
    if isinstance(subsystem, dict):
        return dict(subsystem)
    return {"name": getattr(subsystem, "name", "")}


def artifact_root_of(inputs: Any) -> str | None:
    """The artifact-root hint carried on inputs (None when absent)."""
    value = getattr(inputs, "artifact_root", None)
    return str(value) if value else None


def _default_budget(mock: bool) -> float | None:
    """Replays default to the script's cheap cap in real mode; mock is free."""
    return None if mock else 0.05


class _capture_clients:
    """Record the invocation rows of every model client built inside the block.

    Activities build their model client internally (``MockModelClient`` in
    mock mode, ``build_model_client`` otherwise) and persist its invocation
    list through ``persist_model_invocations(db_path, ...)``. Because replay
    passes ``db_path=None`` (read-only guarantee), those rows would be
    discarded — so this hook wraps both construction sites in the activity
    modules and appends every built client to the sink; the runner serialises
    each client's invocations after the activity returns for out-of-band,
    replay-tagged recording.
    """

    def __init__(self, sink: list[dict[str, Any]]) -> None:
        self._sink = sink
        self._patched: dict[tuple[Any, str], Any] = {}
        self._built: list[Any] = []

    def __enter__(self) -> _capture_clients:
        import quarry_activities.gapfill as gapfill_mod
        import quarry_activities.hunt as hunt_mod
        import quarry_activities.prove as prove_mod
        import quarry_activities.recon_subsystem as recon_mod
        import quarry_activities.tracer as tracer_mod
        import quarry_activities.validate as validate_mod
        from quarry_models.factory import build_model_client
        from quarry_models.mock_client import MockModelClient

        real_mock = MockModelClient
        real_factory = build_model_client
        built = self._built

        def mock_wrapper(*args: Any, **kwargs: Any) -> Any:
            client = real_mock(*args, **kwargs)
            built.append(client)
            return client

        def factory_wrapper(*args: Any, **kwargs: Any) -> Any:
            client = real_factory(*args, **kwargs)
            built.append(client)
            return client

        for mod in (gapfill_mod, hunt_mod, prove_mod, recon_mod, tracer_mod, validate_mod):
            if hasattr(mod, "MockModelClient"):
                self._patched[(mod, "MockModelClient")] = mod.MockModelClient
                mod.MockModelClient = mock_wrapper
            if hasattr(mod, "build_model_client"):
                self._patched[(mod, "build_model_client")] = mod.build_model_client
                mod.build_model_client = factory_wrapper
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        del exc_type, exc, tb
        for (mod, attr), original in self._patched.items():
            setattr(mod, attr, original)
        self._patched.clear()
        for client in self._built:
            self._sink.extend(_client_invocation_rows(client))
        self._built.clear()


def envelope_to_json(envelope: dict[str, Any]) -> str:
    """Serialise a replay envelope for CLI printing."""
    return json.dumps(envelope, indent=2, default=str)


__all__ = [
    "MockPanelError",
    "ReplayResolutionError",
    "config_panel_name",
    "envelope_to_json",
    "run_replay",
    "stage_names",
    "tag_invocations_as_replay",
]
