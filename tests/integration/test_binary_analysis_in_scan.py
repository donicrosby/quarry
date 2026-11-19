"""Integration test: binary analysis feeds the hunt stage end to end (C6).

Chains the REAL pieces — the deterministic ``binary-analysis`` activity persisting
a hardening report, the hunt activity's consumption-time merge, the real hunt
prompt rendering — to prove the report reaches a ``security_misconfiguration``
hunt task's effective ``domain_context``, never reaches a task of another class,
and degrades to a no-op when the artifact is absent. A gapfill-emitted re-hunt
task of the matching class receives the report the same way.

A full Temporal RunScanWorkflow e2e is not used here for the same reason noted in
tests/integration/test_context_injector_e2e.py: the local Temporal dev server is
not available in every environment. Chaining the real activity + real
consumption path exercises every binary-analysis-specific code path.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.schemas import AgentTask, CoverageLedger, VulnerabilityClass
from quarry_activities.binary_analysis import binary_analysis_activity
from quarry_activities.gapfill import gapfill_impl
from quarry_activities.hunt import hunt_activity, hunt_impl
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec
from quarry_plugins.context.binary_analysis_context import BINARY_ANALYSIS_ARTIFACT_KEY

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


class _NoFindingHuntResponse(BaseModel):
    findings: list[object] = []
    tool_calls: list[object] = []


class _GapfillResponse(BaseModel):
    gaps: list[dict[str, Any]] = []
    tool_calls: list[object] = []


def _repo_with_binary(tmp_path: Path) -> Path:
    """Create a repo containing one compiled ELF binary; skip without gcc."""
    if shutil.which("gcc") is None:
        import pytest

        pytest.skip("gcc unavailable")
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.c"
    source.write_text(
        '#include <stdio.h>\nint main(void){ puts("BINARYANALYSISMARKER"); return 0; }\n',
        encoding="utf-8",
    )
    subprocess.run(
        ["gcc", f"-o{repo / 'app'}", str(source)], check=True, capture_output=True, text=True
    )
    return repo


def _task(vuln_class: VulnerabilityClass, repo: Path) -> AgentTask:
    return AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name=f"hunt-{vuln_class.value}",
        vuln_class=vuln_class,
        scope=".",
        task_prompt="Inspect the target.",
        status="pending",
        created_at=_NOW,
    )


def _render_hunt_prompt(task: AgentTask, repo: Path) -> str:
    """Run hunt_impl with a capturing mock and return the first rendered prompt."""
    captured: list[Any] = []

    class _CapturingMock(MockModelClient):
        def __init__(self) -> None:
            super().__init__(default=_NoFindingHuntResponse())

        def complete_structured(self, request: Any, response_model: Any) -> Any:  # type: ignore[override]
            captured.append(request)
            return super().complete_structured(request, response_model)

    hunt_impl(
        task=task,
        repo_path=str(repo),
        max_iterations=1,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=_CapturingMock(),
    )
    assert captured, "expected at least one model call"
    return "\n".join(message.content for message in captured[0].messages)


def test_binary_analysis_in_scan_injects_into_security_misconfiguration_task(
    tmp_path: Path,
) -> None:
    repo = _repo_with_binary(tmp_path)
    artifact_root = tmp_path / "artifacts"
    # Real deterministic activity persists the report.
    result = binary_analysis_activity(str(repo), str(artifact_root))
    assert result["artifact_key"] == BINARY_ANALYSIS_ARTIFACT_KEY
    assert (artifact_root / BINARY_ANALYSIS_ARTIFACT_KEY).exists()

    # Real hunt activity consumes it at execution time.
    payload = hunt_activity(
        _task(VulnerabilityClass.SECURITY_MISCONFIGURATION, repo).model_dump(mode="json"),
        str(repo),
        1,
        None,
        None,
        artifact_root=str(artifact_root),
    )
    task = AgentTask.model_validate(payload["task"])
    assert '"binaries"' in task.domain_context
    assert "app" in task.domain_context
    assert "binary_analysis" in task.domain_context_sources

    # And the merged context reaches the model's rendered prompt.
    prompt = _render_hunt_prompt(task, repo)
    assert '"binaries"' in prompt
    assert "BINARYANALYSISMARKER" in prompt


def test_binary_analysis_in_scan_skips_other_classes(tmp_path: Path) -> None:
    repo = _repo_with_binary(tmp_path)
    artifact_root = tmp_path / "artifacts"
    binary_analysis_activity(str(repo), str(artifact_root))

    payload = hunt_activity(
        _task(VulnerabilityClass.COMMAND_INJECTION, repo).model_dump(mode="json"),
        str(repo),
        1,
        None,
        None,
        artifact_root=str(artifact_root),
    )
    task = AgentTask.model_validate(payload["task"])
    assert "binary_analysis" not in task.domain_context_sources
    assert '"binaries"' not in task.domain_context


def test_binary_analysis_in_scan_missing_artifact_is_noop(tmp_path: Path) -> None:
    repo = _repo_with_binary(tmp_path)
    artifact_root = tmp_path / "artifacts"  # never populated

    payload = hunt_activity(
        _task(VulnerabilityClass.SECURITY_MISCONFIGURATION, repo).model_dump(mode="json"),
        str(repo),
        1,
        None,
        None,
        artifact_root=str(artifact_root),
    )
    task = AgentTask.model_validate(payload["task"])
    assert task.domain_context_sources == []
    assert '"binaries"' not in task.domain_context


def test_binary_analysis_in_scan_gapfill_rehunt_gets_report(tmp_path: Path) -> None:
    repo = _repo_with_binary(tmp_path)
    artifact_root = tmp_path / "artifacts"
    binary_analysis_activity(str(repo), str(artifact_root))

    ledger = CoverageLedger(
        id="ledger-1",
        scan_id="scan-1",
        workspace_id="ws-1",
        agent_tasks_total=1,
        agent_tasks_scanned=1,
        vuln_classes_requested=[VulnerabilityClass.SECURITY_MISCONFIGURATION],
        vuln_classes_completed=[],
        created_at=_NOW,
    )
    client = MockModelClient(default=_GapfillResponse(gaps=[]))
    tasks = gapfill_impl(
        ledger=ledger,
        existing_tasks=[],
        vuln_classes=[VulnerabilityClass.SECURITY_MISCONFIGURATION],
        repo_path=str(repo),
        scan_id="scan-1",
        client=client,
        hunter_gaps=[
            {
                "area": "bin/",
                "reason": "did not inspect the compiled helper",
                "vuln_class": "security_misconfiguration",
            }
        ],
        artifact_root=str(artifact_root),
    )
    rehunts = [
        task for task in tasks if task.vuln_class == VulnerabilityClass.SECURITY_MISCONFIGURATION
    ]
    assert rehunts, tasks
    assert '"binaries"' in rehunts[0].domain_context
    assert "binary_analysis" in rehunts[0].domain_context_sources
