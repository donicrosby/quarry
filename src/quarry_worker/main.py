"""Temporal worker entrypoint."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.worker import Worker

from quarry.config import QuarrySettings
from quarry_activities.attack_surface import extract_fastapi_routes, extract_fastapi_routes_for_repo
from quarry_activities.coverage import build_coverage_ledger_activity
from quarry_activities.diff import git_diff_commits
from quarry_activities.dynamic_validation import (
    validate_command_injection_candidate_activity,
    validate_idor_candidate_activity,
)
from quarry_activities.integrations import deliver_integrations_activity
from quarry_activities.mapper import map_impacted_regions
from quarry_activities.provenance import build_scan_manifest_activity
from quarry_activities.recon_orchestrator import recon_orchestrator_activity
from quarry_activities.recon_subsystem import recon_subsystem_activity
from quarry_activities.recon_synthesis import recon_synthesis_activity
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.validation import (
    promote_to_final_finding_metadata,
    validate_secret_candidate,
)
from quarry_plugins.vuln_classes.command_injection import (
    scan_attack_surface_for_command_injection,
)
from quarry_plugins.vuln_classes.idor import scan_attack_surface_for_idor
from quarry_plugins.vuln_classes.secrets import scan_repo_for_secrets
from quarry_workflows import RunDiffScanWorkflow, RunScanWorkflow
from quarry_workflows.recon import ReconWorkflow


async def run_worker() -> None:
    settings = QuarrySettings()
    client = await Client.connect(
        settings.temporal_address,
        data_converter=pydantic_data_converter,
    )
    worker = Worker(
        client,
        task_queue="quarry-control",
        workflows=[RunScanWorkflow, RunDiffScanWorkflow, ReconWorkflow],
        activities=[
            create_repository_snapshot,
            persist_scan_state,
            extract_fastapi_routes,
            extract_fastapi_routes_for_repo,
            git_diff_commits,
            map_impacted_regions,
            scan_repo_for_secrets,
            scan_attack_surface_for_idor,
            scan_attack_surface_for_command_injection,
            validate_secret_candidate,
            validate_idor_candidate_activity,
            validate_command_injection_candidate_activity,
            promote_to_final_finding_metadata,
            build_coverage_ledger_activity,
            deliver_integrations_activity,
            build_scan_manifest_activity,
            render_markdown_report_activity,
            recon_orchestrator_activity,
            recon_subsystem_activity,
            recon_synthesis_activity,
        ],
        activity_executor=ThreadPoolExecutor(max_workers=10),
        graceful_shutdown_timeout=timedelta(seconds=30),
    )
    await worker.run()


def main() -> None:
    asyncio.run(run_worker())
