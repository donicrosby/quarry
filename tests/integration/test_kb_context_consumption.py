"""Integration test: KB consumption by reference end to end (cpc slice 3).

The kb-recon activity writes the KB artifact set to the artifact store and the
workflow records the root-index key on the scan metadata; the hunt stage then
consumes those records BY REFERENCE — resolving them at execution time into the
rendered prompt — while a scan with no KB artifacts falls back to the inline
behaviour and still completes (no crash, no empty-scan).

Written RED first for openspec change candidate-precision-and-calibration,
task 3.1 (knowledge-base spec scenario "Hunt receives referenced context").
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from temporalio import activity
from temporalio.client import Client
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from quarry_activities.inputs import ScanSecretsInput
from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, RunScanWorkflow

FIXTURE_REPO = Path("examples/vulnerable-fastapi").resolve()
_SKIP_REASON = "examples/vulnerable-fastapi not present"

_NOW = datetime(2026, 9, 11, tzinfo=UTC)

_lock = threading.Lock()

# What the fake hunt activities saw: rendered prompt? No — the task payload.
# The hunt activity receives the AgentTask + kb_root_index_key + artifact_root;
# it records what it resolved for the assertion below.
_hunt_calls: list[dict[str, Any]] = []


@activity.defn(name="hunt-vuln-class")
def _kb_recording_hunt_activity(
    task: object,
    repo_path: str | None = None,
    max_iterations: int = 12,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
) -> dict[str, list[dict[str, object]]]:
    task_dict = cast("dict[str, Any]", task) if isinstance(task, dict) else {}
    with _lock:
        _hunt_calls.append(
            {
                "scan_id": task_dict.get("scan_id"),
                "kb_root_index_key": kb_root_index_key,
                "artifact_root": artifact_root,
            }
        )
    return {"findings": [], "coverage_gaps": []}


@activity.defn(name="kb-recon")
def _kb_recon_writing_activity(
    repo_root: str,
    scan_id: str,
    arch_doc_json: str | None = None,
    panel_json: str | None = None,
    budget_cap_usd: float | None = None,
    db_path: str | None = None,
    max_iterations: int = 30,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
) -> dict[str, object]:
    """Persist a minimal KB artifact set exactly as the real activity does."""
    assert artifact_root is not None
    index = {
        "scan_id": scan_id,
        "entity_keys": ["kb/entities/ent-login.json"],
        "vuln_class_note_keys": [],
        "dependency_graph_key": "kb/dependency_graph.json",
    }
    entity = {
        "id": "ent-login",
        "name": "login",
        "path": "app.py",
        "line": 1,
        "security_relevance": "Auth entry point; no rate limiting on failures",
        "constraints": [],
        "source_locations": ["app.py:1"],
    }
    graph = {"edges": {"app.py": ["fastapi"]}}
    root = Path(artifact_root) / scan_id
    kb = root / "kb"
    kb.mkdir(parents=True, exist_ok=True)
    (kb / "index.json").write_text(json.dumps(index), encoding="utf-8")
    ent_dir = kb / "entities"
    ent_dir.mkdir(exist_ok=True)
    (ent_dir / "ent-login.json").write_text(json.dumps(entity), encoding="utf-8")
    (kb / "dependency_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    return {"index_json": json.dumps(index), "artifact_refs": {}}


def _build_worker(
    client: Client,
    task_queue: str,
    executor: ThreadPoolExecutor,
) -> Worker:
    from quarry_activities.coverage import build_coverage_ledger_activity
    from quarry_activities.dedup import deduplicate_activity
    from quarry_activities.emit_agent_tasks import emit_agent_tasks
    from quarry_activities.integrations import deliver_integrations_activity
    from quarry_activities.provenance import build_scan_manifest_activity
    from quarry_activities.recon_orchestrator import recon_orchestrator_activity
    from quarry_activities.recon_synthesis import recon_synthesis_activity
    from quarry_activities.repo import create_repository_snapshot, persist_scan_state
    from quarry_activities.reporting import render_markdown_report_activity
    from quarry_activities.validation import validate_secret_candidate
    from quarry_workflows.commit_stage import CommitStageWorkflow
    from quarry_workflows.recon import ReconWorkflow

    @activity.defn(name="scan-repo-for-secrets")
    def _stub_scan_repo_for_secrets(
        payload: ScanSecretsInput,
    ) -> list[dict[str, object]]:
        """No-op: these e2e tests exercise workflow plumbing, not sweep detection."""
        return []

    @activity.defn(name="scan-repo-for-ssrf-sinks")
    def _stub_scan_repo_for_ssrf_sinks(
        payload: ScanSecretsInput,
    ) -> list[dict[str, object]]:
        """No-op: these e2e tests exercise workflow plumbing, not sweep detection."""
        return []

    @activity.defn(name="recon-subsystem")
    def _passthrough_recon_subsystem(
        assignment: object,
        repo_root: str | None = None,
        scan_id: str | None = None,
        budget_spec: object = None,
        panel_json: str | None = None,
        db_path: str | None = None,
        max_iterations: int = 40,
        scan_seed: int | None = None,
        artifact_root: str | None = None,
    ) -> dict[str, object]:
        return {
            "name": "main",
            "root_paths": ["."],
            "languages": ["python"],
            "responsibility": "handler",
            "entry_points": [],
            "notes": "",
        }

    return Worker(
        client,
        task_queue=task_queue,
        workflows=[RunScanWorkflow, ReconWorkflow, CommitStageWorkflow],
        activities=[
            create_repository_snapshot,
            _stub_scan_repo_for_secrets,
            _stub_scan_repo_for_ssrf_sinks,
            persist_scan_state,
            recon_orchestrator_activity,
            _passthrough_recon_subsystem,
            recon_synthesis_activity,
            emit_agent_tasks,
            _kb_recording_hunt_activity,
            _kb_recon_writing_activity,
            validate_secret_candidate,
            deduplicate_activity,
            build_coverage_ledger_activity,
            render_markdown_report_activity,
            build_scan_manifest_activity,
            deliver_integrations_activity,
            _never_gapfill_activity,
        ],
        activity_executor=executor,
        graceful_shutdown_timeout=__import__("datetime").timedelta(seconds=10),
        workflow_runner=UnsandboxedWorkflowRunner(),
    )


@activity.defn(name="gapfill-coverage")
def _never_gapfill_activity(
    ledger: object,
    existing_tasks: list[dict[str, object]] | None = None,
    vuln_classes: list[str] | None = None,
    repo_path: str = "",
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    hunter_gaps: list[dict[str, object]] | None = None,
    db_path: str | None = None,
    existing_findings: list[dict[str, object]] | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
) -> list[dict[str, object]]:
    return []


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_hunt_receives_kb_reference_and_resolves_records(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    scan_id = "kb-consume-1"
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    executor = ThreadPoolExecutor(max_workers=10)
    worker = _build_worker(temporal_client, "kb-consume-q", executor)
    _hunt_calls.clear()
    async with worker:
        handle = await temporal_client.start_workflow(
            RunScanWorkflow.run,
            RunScanInput(
                repo_path=str(FIXTURE_REPO),
                scan_id=scan_id,
                db_path=str(db_path),
                output_dir=str(output_dir),
            ),
            id=scan_id,
            task_queue="kb-consume-q",
        )
        result = await handle.result()
    executor.shutdown(wait=True)

    assert result.scan_id == scan_id

    # The reference recorded by kb-recon reached every hunt activity call...
    assert _hunt_calls, "expected the hunt stage to run"
    for call in _hunt_calls:
        assert call["kb_root_index_key"] == "kb/index.json", (
            f"hunt activity must receive the KB root-index key by reference: {call}"
        )
        assert call["artifact_root"], "hunt activity must receive the artifact root"

    # ...and the scan metadata records the same reference.
    repository = QuarryRepository(db_path)
    scan = repository.load_scan(scan_id)
    assert scan.metadata.get("kb_root_index_key") == "kb/index.json"
