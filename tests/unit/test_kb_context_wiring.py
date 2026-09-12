"""Tests: the KB root-index reference flows from scan metadata onto hunt tasks
(cpc slice 3, task 3.1 — the reference side of consumption by reference).

Written RED first. The kb-recon stage records ``kb_root_index_key`` on the scan
metadata; the workflow threads it through emit-agent-tasks (stamping each
hunt AgentTask), the gapfill planner, and validate, together with the artifact
root the stage will resolve it from. All of this is orchestration-only — the
workflow itself never touches the store.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime

from quarry.schemas import (
    AgentTask,
    ArchitectureDoc,
    EntryPoint,
    Subsystem,
    VulnerabilityClass,
)

_NOW = datetime(2026, 9, 11, tzinfo=UTC)


def _arch_doc_json() -> str:
    doc = ArchitectureDoc(
        repo_languages=["python"],
        primary_language="python",
        repo_type="web_service",
        subsystems=[
            Subsystem(
                name="app",
                root_paths=["."],
                languages=["python"],
                responsibility="handler",
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


class TestAgentTaskSchema:
    def test_task_defaults_carry_no_kb_reference(self) -> None:
        task = AgentTask(
            id="t",
            scan_id="s",
            role="hunt",
            task_name="n",
            status="pending",
            created_at=_NOW,
        )
        assert task.kb_root_index_key is None

    def test_task_roundtrips_kb_reference(self) -> None:
        task = AgentTask(
            id="t",
            scan_id="s",
            role="hunt",
            task_name="n",
            status="pending",
            created_at=_NOW,
            kb_root_index_key="kb/index.json",
        )
        restored = AgentTask.model_validate(task.model_dump(mode="json"))
        assert restored.kb_root_index_key == "kb/index.json"


class TestEmitAgentTasksKbReference:
    def test_tasks_stamped_with_kb_reference(self) -> None:
        from quarry_activities.emit_agent_tasks import emit_agent_tasks

        emitted = emit_agent_tasks(
            "scan-1",
            _arch_doc_json(),
            [VulnerabilityClass.SQL_INJECTION.value],
            [],
            kb_root_index_key="kb/index.json",
        )
        assert emitted, "expected at least one task"
        for task_dict in emitted:
            assert task_dict["kb_root_index_key"] == "kb/index.json"

    def test_tasks_have_no_reference_when_kb_absent(self) -> None:
        from quarry_activities.emit_agent_tasks import emit_agent_tasks

        emitted = emit_agent_tasks(
            "scan-1",
            _arch_doc_json(),
            [VulnerabilityClass.SQL_INJECTION.value],
            [],
        )
        assert emitted
        for task_dict in emitted:
            assert task_dict["kb_root_index_key"] is None


class TestWorkflowKbThreading:
    """The workflow records and forwards KB references; it never resolves them."""

    def test_kb_recon_records_root_index_key_on_scan_metadata(self) -> None:
        from importlib import import_module

        run_scan_module = import_module("quarry_workflows.run_scan")

        source = inspect.getsource(run_scan_module)
        assert '"kb_root_index_key"' in source or "'kb_root_index_key'" in source

    def test_workflow_threads_reference_into_emit_hunt_gapfill_validate(self) -> None:
        from importlib import import_module

        run_scan_module = import_module("quarry_workflows.run_scan")

        source = inspect.getsource(run_scan_module)
        # Every KB-consuming activity call receives the reference + root.
        for activity_name in (
            "emit-agent-tasks",
            "hunt-vuln-class",
            "gapfill-coverage",
            "validate-candidate-finding",
        ):
            assert activity_name in source
        assert source.count("kb_root_index_key") >= 4, (
            "the KB root-index key must be threaded to emit/hunt/gapfill/validate"
        )

    def test_hunt_gapfill_validate_accept_kb_parameters(self) -> None:
        from quarry_activities import gapfill, hunt, validate

        assert "kb_root_index_key" in inspect.signature(hunt.hunt_activity).parameters
        assert "kb_root_index_key" in inspect.signature(hunt.hunt_impl).parameters
        assert "kb_root_index_key" in inspect.signature(gapfill.gapfill_activity).parameters
        assert "kb_root_index_key" in inspect.signature(gapfill.gapfill_impl).parameters
        assert "kb_root_index_key" in inspect.signature(validate.validate_activity).parameters
        assert "kb_root_index_key" in inspect.signature(validate.validate_impl).parameters
