"""Per-stage input resolvers for the replay harness (prompt-replay-harness).

Each resolver reconstructs one agentic activity's call arguments from a prior
scan's persisted state — scan DB rows (quarry_persistence) and the artifact
store — exactly as the workflow would have passed them. Resolution is
fail-loud: when a required input cannot be reconstructed, a
:class:`ReplayResolutionError` naming the missing input is raised instead of
fabricating a fallback.

Model routing uses the SAME ``load_quarry_config`` + ``resolve_panel`` path as
a real scan. ``--mock`` selects the all-mock DEFAULT_PANEL explicitly;
without it, a panel that resolves to mock is refused (mirroring
scripts/replay_validate.py) so real spend never silently hits the mock panel.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from quarry.panel_config import (
    ModelTier,
    Provider,
    RoleConfig,
    load_quarry_config,
    resolve_panel,
)
from quarry.schemas import (
    AgentTask,
    ArchitectureDoc,
    CallGraph,
    CandidateFinding,
    CoverageLedger,
    FindingStatus,
    Scan,
    SubsystemAssignment,
)
from quarry_persistence import QuarryRepository
from quarry_tools.call_graph_python import build_python_call_graph


class ReplayResolutionError(Exception):
    """A required replay input could not be reconstructed from persisted state."""


class MockPanelError(ReplayResolutionError):
    """A non-mock replay was requested but the resolved panel role is mock."""


@dataclass(frozen=True)
class PanelSelection:
    """The resolved panel for a replay invocation."""

    panel_name: str
    role: str
    role_config: RoleConfig

    @property
    def is_mock(self) -> bool:
        return self.role_config.provider is Provider.MOCK

    def header_lines(self) -> list[str]:
        """Output header lines labeling the panel for this replay."""
        cfg = self.role_config
        mode = "mock" if self.is_mock else "real"
        return [
            f"replay=1 mode={mode} panel={self.panel_name} role={self.role}",
            f"provider={cfg.provider.value} model={cfg.model or '-'}",
        ]


@dataclass(frozen=True)
class ValidateInputs:
    candidate: CandidateFinding
    repo_path: str
    panel: PanelSelection


@dataclass(frozen=True)
class HuntInputs:
    task: AgentTask
    repo_path: str
    kb_root_index_key: str | None
    panel: PanelSelection
    # The scan's artifact-store root. Threaded so a replay hands the hunt
    # activity the same store the original run wrote its per-agent log to
    # (``runner.artifact_root_of`` reads this field) — replay then appends to
    # the original ``agents/<scan_id>/hunt/<instance_id>.jsonl``.
    artifact_root: str | None = None


@dataclass(frozen=True)
class GapfillInputs:
    ledger: CoverageLedger
    existing_tasks: list[dict[str, Any]]
    repo_path: str
    existing_findings: list[dict[str, Any]]
    kb_root_index_key: str | None
    panel: PanelSelection


@dataclass(frozen=True)
class ProveInputs:
    candidate: CandidateFinding
    repo_path: str
    panel: PanelSelection


@dataclass(frozen=True)
class TraceInputs:
    candidate: CandidateFinding
    call_graph: CallGraph
    repo_path: str
    panel: PanelSelection


@dataclass(frozen=True)
class ReconInputs:
    assignment: SubsystemAssignment
    repo_root: str
    scan_id: str
    panel: PanelSelection


def _mock_panel(panel_name: str, role: str) -> PanelSelection:
    return PanelSelection(
        panel_name=panel_name,
        role=role,
        role_config=RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30),
    )


def _resolve_panel_selection(
    *,
    role: str,
    mock: bool,
    panel_name: str | None,
    allow_mock_panel: bool,
) -> PanelSelection:
    """Resolve the panel via the same path a real scan uses (panel_config).

    ``mock=True`` selects the all-mock DEFAULT_PANEL explicitly. Otherwise the
    named panel (else QUARRY_PANEL / quarry.toml) is resolved through
    ``load_quarry_config`` + ``resolve_panel``; a resulting mock role is
    refused unless ``allow_mock_panel`` is set, mirroring the script's guard
    against paying for a meaningless replay.
    """
    if mock:
        return _mock_panel("mock", role)
    config = load_quarry_config()
    panel = resolve_panel(config, panel_name)
    role_cfg = panel.get(role)
    if role_cfg is None:
        msg = f"panel {panel_name!r} has no {role!r} role"
        raise ReplayResolutionError(msg)
    if role_cfg.provider is Provider.MOCK and not allow_mock_panel:
        msg = (
            f"{role} role resolved to MOCK — check QUARRY_PANEL / quarry.toml "
            "panel config before paying for a replay (or pass --mock explicitly)."
        )
        raise MockPanelError(msg)
    if role_cfg.provider is Provider.MOCK and not panel_name:
        # No named panel and the role fell through to the all-mock DEFAULT_PANEL.
        return _mock_panel("mock", role)
    resolved_name = panel_name or config_panel_name() or "default"
    return PanelSelection(panel_name=resolved_name, role=role, role_config=role_cfg)


def config_panel_name() -> str:
    """The panel name from QUARRY_PANEL (env) — '' when unset."""
    import os

    return os.environ.get("QUARRY_PANEL", "")


def _repository(db_path: str) -> QuarryRepository:
    """Open a repository for one read; the engine is disposed with the repo.

    Resolvers are read-only and short-lived: reading through a fresh engine
    per call keeps replay stateless. Callers must dispose the returned
    repository (``repository.engine.dispose()``) — the ``_read`` helper below
    does this automatically.
    """
    return QuarryRepository(db_path)


def _read(db_path: str, fn: Callable[[QuarryRepository], T]) -> T:
    repository = _repository(db_path)
    try:
        return fn(repository)
    finally:
        repository.engine.dispose()


T = TypeVar("T")


def load_scan(db_path: str, scan_id: str) -> Scan:
    def _load(repository: QuarryRepository) -> Scan:
        try:
            return repository.load_scan(scan_id)
        except ValueError as exc:
            msg = f"unknown scan id {scan_id!r} in {db_path} ({exc})"
            raise ReplayResolutionError(msg) from exc

    return _read(db_path, _load)


def _load_candidates(db_path: str, scan_id: str) -> list[CandidateFinding]:
    return _read(db_path, lambda r: r.load_candidate_findings(scan_id))


def _metadata_str(scan: Scan, key: str) -> str | None:
    raw = scan.metadata.get(key)
    return str(raw) if isinstance(raw, str) and raw else None


def _panel_for_scan_role(
    scan: Scan, role: str, *, mock: bool, panel_name: str | None
) -> PanelSelection:
    """Resolve the panel from the scan's own snapshot when replaying without --mock.

    Real scans freeze their panel into ``scan.panel_snapshot`` (ModelPanelEntry
    list); replaying the SAME panel the scan used is the faithful choice. When
    the snapshot carries no entry for the role, fall through to live
    ``load_quarry_config`` + ``resolve_panel`` resolution.
    """
    if mock:
        return _mock_panel("mock", role)
    entry = next(
        (e for e in scan.panel_snapshot if e.role == role and e.provider != "mock"),
        None,
    )
    if entry is not None:
        tiers = [ModelTier.model_validate(t) for t in entry.tiers]
        return PanelSelection(
            panel_name=f"scan-snapshot:{scan.id}",
            role=role,
            role_config=RoleConfig(
                provider=Provider(entry.provider),
                model=entry.model,
                rpm=entry.rate_limit_rpm,
                turn_timeout_seconds=entry.turn_timeout_seconds,
                tiers=tiers,
                context_window_tokens=entry.context_window_tokens,
                context_window_threshold=entry.context_window_threshold,
            ),
        )
    return _resolve_panel_selection(
        role=role, mock=False, panel_name=panel_name, allow_mock_panel=False
    )


def resolve_validate_inputs(
    *,
    db_path: str,
    scan_id: str,
    repo_path: str,
    vuln_class: str | None,
    panel_name: str | None = None,
    allow_mock_panel: bool = True,
    mock: bool = False,
) -> ValidateInputs:
    """Resolve ``validate_activity(finding, repo_path, panel_json=...)`` inputs."""
    load_scan(db_path, scan_id)
    candidates = _load_candidates(db_path, scan_id)
    if vuln_class:
        candidates = [c for c in candidates if c.vuln_class.value == vuln_class]
    if not candidates:
        msg = f"no candidate findings for scan={scan_id} class={vuln_class or '(any)'} in {db_path}"
        raise ReplayResolutionError(msg)
    panel = _resolve_panel_selection(
        role="validate",
        mock=mock,
        panel_name=panel_name,
        allow_mock_panel=allow_mock_panel,
    )
    return ValidateInputs(
        candidate=candidates[0],
        repo_path=repo_path,
        panel=panel,
    )


def resolve_hunt_inputs(
    *,
    db_path: str,
    scan_id: str,
    repo_path: str,
    vuln_class: str,
    panel_name: str | None = None,
    mock: bool = False,
    artifact_root: str | None = None,
) -> HuntInputs:
    """Resolve ``hunt_activity(task, repo_path, ...)`` inputs from persisted state.

    Unlike the finding-driven stages (whose ids come straight from a persisted
    ``CandidateFinding.id`` / ``scan_id`` / assignment name), hunt tasks are
    re-derived rather than looked up: the resolver rebuilds the task shape from
    the persisted ArchitectureDoc via ``emit_agent_tasks`` itself, so the shape
    cannot drift from the emitter. But the workflow DOES persist every emitted
    task (``save_agent_task`` upsert-by-id), and ``emit_agent_tasks`` mints a
    fresh ``uuid4`` per call — so a lone re-derivation would give the replay a
    new id and write a new, uncorrelated per-agent log. To reconstruct the
    ORIGINAL instance, the fresh derivation is overlaid with the persisted
    task ids (see :func:`_overlay_persisted_task_ids`), so ``run_agent_loop``
    keys the log file off the same id the original run used and the replay
    appends to ``agents/<scan_id>/hunt/<instance_id>.jsonl`` (spec Req-3
    scenario 1).
    """
    scan = load_scan(db_path, scan_id)

    def _doc(repository: QuarryRepository) -> ArchitectureDoc | None:
        return repository.load_architecture_doc(scan_id)

    doc = _read(db_path, _doc)
    if doc is None:
        msg = (
            f"scan {scan_id!r} has no persisted ArchitectureDoc — the recon "
            "stage never completed, so hunt tasks cannot be reconstructed"
        )
        raise ReplayResolutionError(msg)
    tasks = _overlay_persisted_task_ids(
        _emit_tasks(doc, scan_id, scan),
        _read(db_path, lambda r: r.load_agent_tasks(scan_id)),
    )
    matching = [t for t in tasks if t.vuln_class is not None and t.vuln_class.value == vuln_class]
    if not matching:
        requested = sorted({t.vuln_class.value for t in tasks if t.vuln_class is not None})
        msg = (
            f"scan {scan_id!r} produced no hunt task for class {vuln_class!r} "
            f"(scan hunted: {requested or 'nothing'})"
        )
        raise ReplayResolutionError(msg)
    panel = _panel_for_scan_role(scan, "hunt", mock=mock, panel_name=panel_name)
    return HuntInputs(
        task=matching[0],
        repo_path=repo_path,
        kb_root_index_key=_metadata_str(scan, "kb_root_index_key"),
        panel=panel,
        artifact_root=artifact_root,
    )


def _overlay_persisted_task_ids(
    derived: list[AgentTask], persisted: list[AgentTask]
) -> list[AgentTask]:
    """Overlay persisted hunt-task ids onto the freshly re-derived tasks.

    ``emit_agent_tasks`` mints a fresh ``uuid4`` per call, but the workflow
    persists every emitted task (``save_agent_task``), so the original id is
    recoverable from the scan DB and is what keys the per-agent execution log.
    Recon-derived originals (``source == "recon"``, emitted in round 0) are the
    tasks this resolver reproduces; they are keyed by ``task_name`` — the
    (vuln_class, scope) pair the emitter stamps — and their persisted ``id`` is
    copied onto the matching re-derived task. ``task_name`` is unique per pair,
    so a ``setdefault`` (persisted rows arrive ordered by round_index then id)
    keeps the original when a later round re-emitted the same pair.

    A scan with no persisted recon tasks (one predating task persistence)
    leaves the derived tasks untouched: there is no original id to recover and
    the fresh derivation is the only shape available.
    """
    originals: dict[str, AgentTask] = {}
    for task in persisted:
        if task.source == "recon":
            originals.setdefault(task.task_name, task)
    if not originals:
        return derived
    return [
        task.model_copy(update={"id": originals[task.task_name].id})
        if task.task_name in originals
        else task
        for task in derived
    ]


def _emit_tasks(doc: ArchitectureDoc, scan_id: str, scan: Scan) -> list[AgentTask]:
    from quarry_activities.emit_agent_tasks import emit_agent_tasks

    payloads = emit_agent_tasks(
        scan_id=scan_id,
        arch_doc_json=doc.model_dump_json(),
        vuln_classes=[vc.value for vc in scan.profile.vuln_classes],
        plugins_active=list(scan.profile.plugins_active),
        kb_root_index_key=_metadata_str(scan, "kb_root_index_key"),
    )
    return [AgentTask.model_validate(p) for p in payloads]


def resolve_gapfill_inputs(
    *,
    db_path: str,
    scan_id: str,
    repo_path: str,
    artifact_root: str | None,
    panel_name: str | None = None,
    mock: bool = False,
) -> GapfillInputs:
    """Resolve ``gapfill_activity(ledger, ...)`` inputs from persisted state.

    The coverage ledger is only persisted as a COVERAGE_LEDGER artifact (saved
    via ``save_artifact_ref``); the resolver loads the latest such ref and
    reads the ledger JSON back through the artifact store.
    """
    scan = load_scan(db_path, scan_id)
    if not artifact_root:
        msg = "gapfill replay requires --artifact-root (the scan's artifact store root)"
        raise ReplayResolutionError(msg)
    ledger = _load_latest_ledger(artifact_root, scan_id)
    candidates = _load_candidates(db_path, scan_id)
    existing_findings = [
        {
            "vuln_class": f.vuln_class.value,
            "title": f.title,
            "affected_component": f.affected_component or "",
            "root_cause_key": f.root_cause_key or "",
        }
        for f in candidates
    ]

    def _doc(repository: QuarryRepository) -> ArchitectureDoc | None:
        return repository.load_architecture_doc(scan_id)

    tasks_doc = _read(db_path, _doc)
    existing_tasks: list[dict[str, Any]] = (
        [t.model_dump(mode="json") for t in _emit_tasks(tasks_doc, scan_id, scan)]
        if tasks_doc is not None
        else []
    )
    panel = _panel_for_scan_role(scan, "gapfill", mock=mock, panel_name=panel_name)
    return GapfillInputs(
        ledger=ledger,
        existing_tasks=existing_tasks,
        repo_path=repo_path,
        existing_findings=existing_findings,
        kb_root_index_key=_metadata_str(scan, "kb_root_index_key"),
        panel=panel,
    )


def _load_latest_ledger(artifact_root: str, scan_id: str) -> CoverageLedger:
    latest: tuple[str, str] | None = None
    for path in sorted((Path(artifact_root) / scan_id).glob("coverage-*.json")):
        key = path.relative_to(Path(artifact_root)).as_posix()
        latest = (key, path.read_text(encoding="utf-8"))
    if latest is None:
        msg = (
            f"no coverage-ledger artifact for scan={scan_id} under artifact root "
            f"{artifact_root!r} — the COVERAGE stage never ran, so gapfill "
            "inputs cannot be reconstructed"
        )
        raise ReplayResolutionError(msg)
    return CoverageLedger.model_validate_json(latest[1])


def resolve_prove_inputs(
    *,
    db_path: str,
    scan_id: str,
    repo_path: str,
    finding_id: str | None,
    panel_name: str | None = None,
    mock: bool = False,
) -> ProveInputs:
    """Resolve ``prove_activity(finding, repo_path, ...)`` inputs.

    Prove acts only on findings whose status is NEEDS_PROOF
    (``filter_needs_proof``); a --finding-id must name one of those.
    """
    scan = load_scan(db_path, scan_id)
    candidates = _load_candidates(db_path, scan_id)
    provable = [c for c in candidates if c.status == FindingStatus.NEEDS_PROOF]
    if finding_id is not None:
        selected = [c for c in provable if c.id == finding_id]
        if not selected:
            msg = (
                f"finding {finding_id!r} in scan {scan_id!r} is not a needs_proof "
                f"candidate ({len(candidates)} candidates, {len(provable)} provable)"
            )
            raise ReplayResolutionError(msg)
        chosen = selected[0]
    else:
        if not provable:
            msg = (
                f"scan {scan_id!r} has no needs_proof candidates to prove "
                f"({len(candidates)} candidates stored)"
            )
            raise ReplayResolutionError(msg)
        chosen = provable[0]
    panel = _panel_for_scan_role(scan, "prove", mock=mock, panel_name=panel_name)
    return ProveInputs(candidate=chosen, repo_path=repo_path, panel=panel)


def resolve_trace_inputs(
    *,
    db_path: str,
    scan_id: str,
    repo_path: str,
    finding_id: str | None,
    panel_name: str | None = None,
    mock: bool = False,
) -> TraceInputs:
    """Resolve ``tracer_activity(finding, call_graph, repo_path, ...)`` inputs.

    The tracer's CallGraph is derived (build-call-graph), not persisted, so the
    resolver rebuilds it with the same python call-graph backend the workflow's
    build-call-graph activity uses (deterministic from the repo tree).
    """
    scan = load_scan(db_path, scan_id)
    candidates = _load_candidates(db_path, scan_id)
    if finding_id is not None:
        selected = [c for c in candidates if c.id == finding_id]
        if not selected:
            msg = f"finding {finding_id!r} not found among scan {scan_id!r} candidates"
            raise ReplayResolutionError(msg)
        chosen = selected[0]
    else:
        if not candidates:
            msg = f"scan {scan_id!r} has no candidate findings to trace"
            raise ReplayResolutionError(msg)
        chosen = candidates[0]
    language = _metadata_str(scan, "target_language") or "python"
    call_graph = build_python_call_graph(scan_id=scan_id, repo_path=repo_path)
    if language != "python":
        # Non-python replay falls back to an empty graph with the same
        # index_kind the activity warns about — the tracer handles it.
        call_graph = CallGraph(scan_id=scan_id, index_kind="scip")
    panel = _panel_for_scan_role(scan, "trace", mock=mock, panel_name=panel_name)
    return TraceInputs(candidate=chosen, call_graph=call_graph, repo_path=repo_path, panel=panel)


def resolve_recon_inputs(
    *,
    db_path: str,
    scan_id: str,
    repo_path: str,
    sub_index: int,
    panel_name: str | None = None,
    mock: bool = False,
) -> ReconInputs:
    """Resolve the recon trio inputs for one subsystem pass.

    ``recon-orchestrator`` is a pure function of the repo tree (no model call),
    so the resolver runs it to get the assignments the workflow would fan out,
    then selects assignment[sub_index] for ``recon_subsystem_activity``.
    """
    from quarry_activities.recon_orchestrator import recon_orchestrator_activity

    scan = load_scan(db_path, scan_id)
    assignments: list[SubsystemAssignment] = recon_orchestrator_activity(repo_path, scan_id)
    if sub_index >= len(assignments):
        msg = (
            f"recon orchestrator produced {len(assignments)} subsystem assignments "
            f"for repo {repo_path!r}; no assignment at index {sub_index}"
        )
        raise ReplayResolutionError(msg)
    panel = _panel_for_scan_role(scan, "recon", mock=mock, panel_name=panel_name)
    return ReconInputs(
        assignment=assignments[sub_index],
        repo_root=repo_path,
        scan_id=scan_id,
        panel=panel,
    )
