"""CyberGym benchmark runner: per-task orchestration → BenchmarkRunResult.

Per task: materialize (HF download) → reproduce (agent loop, role ``prove``)
→ verify (docker dual-run) → TaskOutcome. Task-level failures (agent failed,
verifier infra error, missing reference PoC) are captured as ``error`` on the
outcome — the suite never aborts. Provenance (models, prompt hashes, config,
harness SHA) is mandatory on every artifact.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from quarry.benchmark_artifacts import (
    BenchmarkMetrics,
    BenchmarkRunResult,
    RunProvenance,
    TaskOutcome,
)
from quarry_benchmark.agent import SYSTEM_PROMPT, AgentFailed, reproduce
from quarry_benchmark.cybergym import CybergymTask, materialize
from quarry_benchmark.verifier import CybergymVerdict, VerifierError, verify

if TYPE_CHECKING:
    from quarry_benchmark.cybergym import Fetch

_log = logging.getLogger(__name__)

ExecRunner = Callable[[list[str], float], subprocess.CompletedProcess[str]]
ClientFactory = Callable[[str], Any]


def httpx_fetch(url: str) -> bytes:
    """Production fetch: unauthenticated GET from the HF dataset."""
    import httpx

    response = httpx.get(url, timeout=120.0, follow_redirects=True)
    response.raise_for_status()
    return response.content


def git_sha() -> str:
    """Harness git SHA for provenance (falls back to 'unknown-<tree-hash>')."""
    import subprocess as sp

    try:
        return sp.run(  # noqa: S603 — fixed argv
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, sp.SubprocessError):
        return "unknown"


def docker_available() -> bool:
    """Preflight: can we reach a docker daemon? (CLI infra-error gate.)"""
    import subprocess as sp

    try:
        completed = sp.run(  # noqa: S603 — fixed argv
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, sp.SubprocessError):
        return False
    return completed.returncode == 0


def _panel_model_for_prove() -> str:
    """role → provider/model string from the panel (used for provenance)."""
    from quarry_models.panel import resolve

    slot = resolve("prove")
    return f"{slot.provider}/{slot.model}"


def _prompt_hashes() -> dict[str, str]:
    """sha256[:12] of the prompts actually sent (system + seed user template)."""
    return {
        "prove.system": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()[:12],
    }


def _reference_poc_path(reference_poc_dir: Path, task_id: str) -> Path | None:
    """Locate a staged reference PoC: ``<dir>/<task_id with _>/>_poc.bin``."""
    candidate = reference_poc_dir / f"{task_id.replace(':', '_')}_poc.bin"
    return candidate if candidate.is_file() else None


def run_cybergym_benchmark(
    tasks: list[CybergymTask],
    *,
    level: str,
    work_dir: Path | str,
    harness_sha: str,
    client_factory: ClientFactory,
    fetch: Fetch | None = None,
    exec_runner: ExecRunner | None = None,
    verify_only: bool = False,
    reference_poc_dir: Path | str | None = None,
    budget_usd: float = 2.0,
    max_iterations: int = 40,
    run_id: str | None = None,
) -> BenchmarkRunResult:
    """Run the CyberGym benchmark over ``tasks``; returns the full artifact."""

    work_dir = Path(work_dir)
    started_wall = time.monotonic()
    fetch = fetch or httpx_fetch
    outcomes: list[TaskOutcome] = []

    for task in tasks:
        started = time.monotonic()
        outcome = _run_single_task(
            task,
            level=level,
            work_dir=work_dir,
            client_factory=client_factory,
            fetch=fetch,
            exec_runner=exec_runner,
            verify_only=verify_only,
            reference_poc_dir=Path(reference_poc_dir) if reference_poc_dir else None,
            budget_usd=budget_usd,
            max_iterations=max_iterations,
        )
        outcomes.append(outcome)
        _log.info(
            "cybergym %s: solved=%s vul=%s fix=%s (%.1fs)",
            outcome.task_id,
            outcome.solved,
            outcome.vul_exit_code,
            outcome.fix_exit_code,
            time.monotonic() - started,
        )

    solved_count = sum(1 for o in outcomes if o.solved)
    total_cost = sum(o.cost_usd for o in outcomes)
    metrics = BenchmarkMetrics(
        proof_rate=solved_count / len(outcomes) if outcomes else 0.0,
        token_cost_per_proven_finding=total_cost / solved_count if solved_count else 0.0,
        wall_clock_seconds=time.monotonic() - started_wall,
    )
    config: dict[str, Any] = {
        "mode": "verify-only" if verify_only else "agent",
        "level": level,
        "budget_usd": budget_usd,
        "max_iterations": max_iterations,
        "task_count": len(tasks),
    }
    if verify_only:
        config["reference_poc_dir"] = str(reference_poc_dir)
    provenance = RunProvenance(
        models={"prove": _panel_model_for_prove()} if not verify_only else {},
        prompt_hashes=_prompt_hashes() if not verify_only else {},
        config=config,
        harness_sha=harness_sha,
    )
    return BenchmarkRunResult(
        run_id=run_id or f"cybergym-{level}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}",
        benchmark="cybergym",
        level=level,
        metrics=metrics,
        provenance=provenance,
        tasks=outcomes,
    )


def _run_single_task(
    task: CybergymTask,
    *,
    level: str,
    work_dir: Path,
    client_factory: ClientFactory,
    fetch: Fetch,
    exec_runner: ExecRunner | None,
    verify_only: bool,
    reference_poc_dir: Path | None,
    budget_usd: float,
    max_iterations: int,
) -> TaskOutcome:
    """Materialize → reproduce → verify one task; failures become ``error``."""
    from quarry_models.types import BudgetSpec

    started = time.monotonic()
    cost = 0.0
    input_tokens = 0
    output_tokens = 0
    try:
        materialized = materialize(task, level, work_dir, fetch=fetch)
    except Exception as exc:  # noqa: BLE001 — per-task isolation, recorded
        return _outcome(task, False, error=f"materialize failed: {exc}", started=started)

    poc_kwargs: dict[str, Any] = {"exec_runner": exec_runner} if exec_runner is not None else {}
    if verify_only:
        if reference_poc_dir is None:
            return _outcome(task, False, error="reference poc dir not provided", started=started)
        ref = _reference_poc_path(reference_poc_dir, task.task_id)
        if ref is None:
            return _outcome(
                task,
                False,
                error=f"reference poc not staged for {task.task_id}",
                started=started,
            )
        try:
            verdict = verify(ref, task.task_id, **poc_kwargs)
        except VerifierError as exc:
            return _outcome(task, False, error=f"verifier: {exc}", started=started)
        return _verdict_outcome(task, verdict, cost, input_tokens, output_tokens, started)

    try:
        agent_outcome = reproduce(
            materialized,
            client=client_factory(task.task_id),
            budget=BudgetSpec(max_cost_usd=budget_usd),
            max_iterations=max_iterations,
            work_dir=work_dir / task.task_id,
        )
        cost = agent_outcome.cost_usd
        input_tokens = agent_outcome.input_tokens
        output_tokens = agent_outcome.output_tokens
    except AgentFailed as exc:
        return _outcome(
            task,
            False,
            error=f"agent failed: {exc}",
            started=started,
            cost=cost,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
    except Exception as exc:  # noqa: BLE001 — per-task isolation
        return _outcome(
            task,
            False,
            error=f"agent error: {exc}",
            started=started,
            cost=cost,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

    try:
        verdict = verify(agent_outcome.poc_path, task.task_id, **poc_kwargs)
    except VerifierError as exc:
        return _outcome(
            task,
            False,
            error=f"verifier: {exc}",
            started=started,
            cost=cost,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
    return _verdict_outcome(task, verdict, cost, input_tokens, output_tokens, started)


def _verdict_outcome(
    task: CybergymTask,
    verdict: CybergymVerdict,
    cost: float,
    input_tokens: int,
    output_tokens: int,
    started: float,
) -> TaskOutcome:
    return TaskOutcome(
        task_id=task.task_id,
        solved=verdict.solved,
        vul_exit_code=verdict.vul_exit_code,
        fix_exit_code=verdict.fix_exit_code,
        cost_usd=cost,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        wall_clock_seconds=time.monotonic() - started,
    )


def _outcome(
    task: CybergymTask,
    solved: bool,
    *,
    error: str,
    started: float,
    cost: float = 0.0,
    input_tokens: int = 0,
    output_tokens: int = 0,
    **_extra: Any,
) -> TaskOutcome:
    return TaskOutcome(
        task_id=task.task_id,
        solved=solved,
        cost_usd=cost,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        wall_clock_seconds=time.monotonic() - started,
        error=error,
    )
