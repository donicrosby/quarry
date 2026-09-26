"""Test worker registration and configuration."""

from quarry_activities.coverage import build_coverage_ledger_activity
from quarry_activities.emit_agent_tasks import emit_agent_tasks
from quarry_activities.hunt import hunt_activity
from quarry_activities.recon_orchestrator import recon_orchestrator_activity
from quarry_activities.repo import create_repository_snapshot
from quarry_activities.reporting import render_markdown_report
from quarry_activities.validation import (
    promote_to_final_finding_metadata,
    validate_secret_candidate,
)
from quarry_worker.main import run_worker


class TestWorkerImports:
    def test_run_worker_function_exists(self) -> None:
        assert callable(run_worker)

    def test_all_activities_importable(self) -> None:
        activities = [
            create_repository_snapshot,
            recon_orchestrator_activity,
            emit_agent_tasks,
            hunt_activity,
            validate_secret_candidate,
            promote_to_final_finding_metadata,
            build_coverage_ledger_activity,
            render_markdown_report,
        ]
        assert len(activities) == 8
        for act in activities:
            assert callable(act)


class TestActivityDecorators:
    def test_all_activities_are_functions(self) -> None:
        activities = [
            create_repository_snapshot,
            recon_orchestrator_activity,
            emit_agent_tasks,
            hunt_activity,
            validate_secret_candidate,
            promote_to_final_finding_metadata,
            build_coverage_ledger_activity,
            render_markdown_report,
        ]
        for act in activities:
            assert callable(act)


class TestWorkerConfiguration:
    def test_task_queue_name(self) -> None:
        import inspect

        from quarry_worker.main import run_worker

        source = inspect.getsource(run_worker)
        assert 'task_queue="quarry-control"' in source

    def test_thread_pool_executor_configured(self) -> None:
        import inspect

        from quarry_worker.main import run_worker

        source = inspect.getsource(run_worker)
        assert "ThreadPoolExecutor(max_workers=10)" in source
        assert "activity_executor=ThreadPoolExecutor" in source

    def test_uses_quarry_settings(self) -> None:
        import inspect

        from quarry_worker.main import run_worker

        source = inspect.getsource(run_worker)
        assert "QuarrySettings()" in source
        assert "settings.temporal_address" in source
