"""End-to-end verification of the context-injector capability.

Chains the REAL pieces — entry-point-discovered plugins (no monkeypatching of
importlib.metadata; both OSS stubs are genuinely registered in pyproject.toml),
the real emit_agent_tasks activity, and the real hunt_impl prompt-rendering
path — to prove domain context actually reaches a rendered hunt prompt for a
matching repo, and never does for a generic one.

A full Temporal RunScanWorkflow e2e was not used here for the same reason
noted in test_lifecycle_hooks_e2e.py / test_lifecycle_dispatch_wiring.py:
post pure-agentic-pivot, every existing e2e scan test relies on a
MockModelClient that yields zero candidate findings, and recon's real
repo_type inference only happens inside the full agentic recon pipeline this
change does not otherwise touch. Chaining the real activity + real prompt
render exercises every context-injector-specific code path without needing
to stand up that machinery.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.schemas import ArchitectureDoc, EntryPoint, Subsystem, VulnerabilityClass
from quarry_activities.emit_agent_tasks import emit_agent_tasks
from quarry_activities.hunt import hunt_impl
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec
from quarry_plugins.base import PluginType
from quarry_plugins.registry import load_plugins, plugins_of_type


class _HuntResponse(BaseModel):
    findings: list[object] = []
    tool_calls: list[object] = []


def _no_finding_response() -> _HuntResponse:
    return _HuntResponse(findings=[], tool_calls=[])


def _arch_doc_json(repo_type: str) -> str:
    doc = ArchitectureDoc(
        repo_languages=["python"],
        primary_language="python",
        repo_type=repo_type,
        subsystems=[
            Subsystem(
                name="main",
                root_paths=["."],
                languages=["python"],
                responsibility="web app",
                entry_points=[
                    EntryPoint(
                        repo="repo-1", file="app.py", function="handler", kind="http_handler"
                    )
                ],
                notes="",
            )
        ],
    )
    return doc.model_dump_json()


def _render_hunt_prompt(task: Any, tmp_path: Path) -> str:
    """Run hunt_impl with a capturing MockModelClient and return the full
    text of the first rendered prompt sent to the model."""
    captured_requests: list[Any] = []

    class _CapturingMock(MockModelClient):
        def __init__(self) -> None:
            super().__init__(default=_no_finding_response())

        def complete_structured(self, request: Any, response_model: Any) -> Any:  # type: ignore[override]
            captured_requests.append(request)
            return super().complete_structured(request, response_model)

    hunt_impl(
        task=task,
        repo_path=str(tmp_path),
        max_iterations=12,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=_CapturingMock(),
    )
    assert captured_requests, "expected at least one model call"
    return "\n".join(m.content for m in captured_requests[0].messages)


def test_real_plugins_are_registered_via_entry_points() -> None:
    """Sanity check: both OSS stubs resolve via the real quarry.plugins group,
    with no importlib.metadata monkeypatching in this test."""
    injectors = plugins_of_type(load_plugins(), PluginType.CONTEXT_INJECTOR)
    names = {p.name for p in injectors}
    assert {"multitenant_isolation", "template_injection"} <= names


def test_matching_repo_gets_domain_context_in_rendered_prompt(tmp_path: Path) -> None:
    emitted = emit_agent_tasks(
        "scan-1",
        _arch_doc_json("saas-multitenant"),
        [VulnerabilityClass.SECRETS.value],
        ["multitenant_isolation"],
    )
    assert len(emitted) == 1
    assert emitted[0]["domain_context_sources"] == ["multitenant_isolation"]

    from quarry.schemas import AgentTask

    task = AgentTask.model_validate(emitted[0])
    prompt_text = _render_hunt_prompt(task, tmp_path)

    assert "## Domain context: multitenant_isolation" in prompt_text


def test_generic_repo_gets_no_domain_context_block(tmp_path: Path) -> None:
    """Golden portability test: both OSS stubs active, generic repo — zero
    '## Domain context:' blocks anywhere in the rendered prompt."""
    from quarry.schemas import AgentTask

    emitted = emit_agent_tasks(
        "scan-1",
        _arch_doc_json("web_service"),
        [VulnerabilityClass.SECRETS.value],
        ["multitenant_isolation", "template_injection"],
    )
    assert len(emitted) == 1
    assert emitted[0]["domain_context"] == ""
    assert emitted[0]["domain_context_sources"] == []

    task = AgentTask.model_validate(emitted[0])
    prompt_text = _render_hunt_prompt(task, tmp_path)

    assert "## Domain context:" not in prompt_text
