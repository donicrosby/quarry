"""Test worker registration and configuration."""

from quarry_activities.attack_surface import extract_fastapi_routes
from quarry_activities.coverage import build_coverage_ledger_activity
from quarry_activities.repo import create_repository_snapshot
from quarry_activities.reporting import render_markdown_report
from quarry_activities.validation import (
    promote_to_final_finding_metadata,
    validate_secret_candidate,
)
from quarry_plugins.vuln_classes.secrets import scan_repo_for_secrets
from quarry_worker.main import run_worker


class TestWorkerImports:
    def test_run_worker_function_exists(self) -> None:
        assert callable(run_worker)

    def test_all_activities_importable(self) -> None:
        activities = [
            create_repository_snapshot,
            extract_fastapi_routes,
            scan_repo_for_secrets,
            validate_secret_candidate,
            promote_to_final_finding_metadata,
            build_coverage_ledger_activity,
            render_markdown_report,
        ]
        assert len(activities) == 7
        for act in activities:
            assert callable(act)


class TestActivityDecorators:
    def test_all_activities_are_functions(self) -> None:
        activities = [
            create_repository_snapshot,
            extract_fastapi_routes,
            scan_repo_for_secrets,
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

    def test_all_activities_registered(self) -> None:
        import inspect

        from quarry_worker.main import run_worker

        source = inspect.getsource(run_worker)
        expected_activities = [
            "create_repository_snapshot",
            "extract_fastapi_routes",
            "scan_repo_for_secrets",
            "validate_secret_candidate",
            "promote_to_final_finding_metadata",
            "build_coverage_ledger_activity",
            "render_markdown_report",
        ]
        for act_name in expected_activities:
            assert act_name in source, f"Activity {act_name} not registered"
