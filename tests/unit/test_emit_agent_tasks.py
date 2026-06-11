"""Unit tests for emit_agent_tasks — the recon→hunt task handoff.

These tests pin the behaviour that an ArchitectureDoc's per-subsystem entry
points are threaded onto the AgentTask for that scope, so the hunter actually
receives recon's leads instead of "(none identified)".
"""

from __future__ import annotations

from quarry.schemas import AgentTask, ArchitectureDoc, EntryPoint, Subsystem, VulnerabilityClass
from quarry_activities.emit_agent_tasks import emit_agent_tasks, task_prompt_for


def _arch_doc_with_entry_points() -> ArchitectureDoc:
    ep = EntryPoint(
        repo=".",
        file="app.py",
        function="fetch_local",
        kind="http_handler",
    )
    return ArchitectureDoc(
        repo_languages=["python"],
        primary_language="python",
        repo_type="web_service",
        subsystems=[
            Subsystem(
                name="app",
                root_paths=["."],
                languages=["python"],
                responsibility="Main application",
                entry_points=[ep],
                notes="SSRF sinks: app.py:84 fetch_local (url param, weak allowlist)",
            )
        ],
    )


def test_tasks_carry_subsystem_entry_points() -> None:
    arch_doc = _arch_doc_with_entry_points()

    raw = emit_agent_tasks(
        "scan-1",
        arch_doc.model_dump_json(),
        ["ssrf"],
    )
    tasks = [AgentTask.model_validate(t) for t in raw]

    assert tasks, "expected at least one task"
    for task in tasks:
        assert task.scope == "."
        assert [ep.function for ep in task.entry_points] == ["fetch_local"]
        assert task.entry_points[0].kind == "http_handler"
        assert "SSRF sinks" in task.recon_notes


def test_tasks_default_to_empty_entry_points_when_none() -> None:
    arch_doc = ArchitectureDoc(
        repo_languages=["python"],
        primary_language="python",
        repo_type="web_service",
        subsystems=[
            Subsystem(
                name="app",
                root_paths=["."],
                languages=["python"],
                responsibility="Main application",
            )
        ],
    )

    raw = emit_agent_tasks("scan-1", arch_doc.model_dump_json(), ["ssrf"])
    tasks = [AgentTask.model_validate(t) for t in raw]

    assert tasks
    assert all(task.entry_points == [] for task in tasks)
    assert all(task.recon_notes == "" for task in tasks)


def test_every_vuln_class_resolves_a_task_stub_from_registry() -> None:
    """Task-prompt stubs live in the prompt registry (prompts/task/*.j2), not in code.

    Every VulnerabilityClass must render a non-empty stub — its own dedicated
    prompts/task/<class>.j2 or the prompts/task/default.j2 fallback.
    """
    for vc in VulnerabilityClass:
        stub = task_prompt_for(vc)
        assert stub, f"no task-prompt stub rendered for {vc.value}"
        assert len(stub) > 20


def test_task_stub_is_registry_backed_not_hardcoded() -> None:
    """Editing prompts/task/<class>.j2 must change the emitted task_prompt (no code dict)."""
    import quarry_activities.emit_agent_tasks as mod

    # The old in-code dict must be gone — stubs are end-user editable in the registry.
    assert not hasattr(mod, "_TASK_PROMPTS")
    assert not hasattr(mod, "_DEFAULT_TASK_PROMPT")
    # A dedicated stub differs from the generic default.
    ssrf_stub = task_prompt_for(VulnerabilityClass.SSRF)
    default_stub = task_prompt_for(VulnerabilityClass.FILE_UPLOAD)
    assert ssrf_stub != default_stub
