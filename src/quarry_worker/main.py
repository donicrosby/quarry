"""Temporal worker entrypoint."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.worker import Worker

from quarry.config import QuarrySettings
from quarry_activities.calibrate import calibrate_activity
from quarry_activities.call_graph import build_call_graph_activity
from quarry_activities.clone import clone_repository_activity
from quarry_activities.coverage import build_coverage_ledger_activity
from quarry_activities.dedup import deduplicate_activity
from quarry_activities.diff import git_diff_commits
from quarry_activities.dynamic_http import http_request_activity
from quarry_activities.dynamic_validate import dynamic_validate_activity
from quarry_activities.emit_agent_tasks import emit_agent_tasks
from quarry_activities.exploit import exploit_turn_activity
from quarry_activities.gapfill import gapfill_activity
from quarry_activities.hunt import hunt_activity
from quarry_activities.integrations import deliver_integrations_activity
from quarry_activities.kb_recon import kb_recon_activity
from quarry_activities.lifecycle_hooks import dispatch_lifecycle_hooks_activity
from quarry_activities.live_recon import live_recon_activity
from quarry_activities.mapper import map_impacted_regions
from quarry_activities.prove import prove_activity
from quarry_activities.provenance import build_scan_manifest_activity
from quarry_activities.read_artifact import read_artifact_text_activity
from quarry_activities.recon_orchestrator import recon_orchestrator_activity
from quarry_activities.recon_subsystem import recon_subsystem_activity
from quarry_activities.recon_synthesis import recon_synthesis_activity
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.sandbox_exec import sandbox_exec_activity
from quarry_activities.tracer import tracer_activity
from quarry_activities.validate import validate_activity as validate_candidate_finding_activity
from quarry_activities.validation import (
    promote_to_final_finding_metadata,
    validate_secret_candidate,
)
from quarry_plugins.vuln_classes.secrets import scan_repo_for_secrets
from quarry_plugins.vuln_classes.ssrf import scan_repo_for_ssrf_sinks
from quarry_workflows import RunDiffScanWorkflow, RunScanWorkflow
from quarry_workflows.commit_stage import CommitStageWorkflow
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
        workflows=[RunScanWorkflow, RunDiffScanWorkflow, ReconWorkflow, CommitStageWorkflow],
        activities=[
            create_repository_snapshot,
            clone_repository_activity,
            persist_scan_state,
            git_diff_commits,
            scan_repo_for_secrets,
            scan_repo_for_ssrf_sinks,
            map_impacted_regions,
            validate_secret_candidate,
            promote_to_final_finding_metadata,
            build_coverage_ledger_activity,
            deliver_integrations_activity,
            dispatch_lifecycle_hooks_activity,
            build_scan_manifest_activity,
            render_markdown_report_activity,
            recon_orchestrator_activity,
            recon_subsystem_activity,
            recon_synthesis_activity,
            emit_agent_tasks,
            hunt_activity,
            kb_recon_activity,
            validate_candidate_finding_activity,
            calibrate_activity,
            dynamic_validate_activity,
            live_recon_activity,
            exploit_turn_activity,
            gapfill_activity,
            deduplicate_activity,
            http_request_activity,
            read_artifact_text_activity,
            sandbox_exec_activity,
            prove_activity,
            tracer_activity,
            build_call_graph_activity,
        ],
        activity_executor=ThreadPoolExecutor(max_workers=10),
        graceful_shutdown_timeout=timedelta(seconds=30),
    )
    await worker.run()


def main() -> None:
    asyncio.run(run_worker())
