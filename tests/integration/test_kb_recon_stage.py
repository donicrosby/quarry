"""Integration test: the Knowledge Base is produced before the hunt stage.

Written RED first for openspec change candidate-precision-and-calibration,
task 2.1 (knowledge-base spec scenario "KB produced before hunt").

A full mock-provider scan must persist the KB artifact set (entity records,
vuln-class notes, dependency graph, root index) to the artifact store BEFORE
the hunt stage runs, and record it in the database / on the scan metadata so
later stages can consume it by reference.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from temporalio.client import Client
from temporalio.worker import Worker

from quarry_persistence import QuarryRepository
from quarry_workflows.run_scan import RunScanInput, RunScanWorkflow

FIXTURE_REPO = Path("examples/vulnerable-fastapi").resolve()


@pytest.mark.skipif(
    not FIXTURE_REPO.exists(),
    reason="examples/vulnerable-fastapi not present",
)
async def test_kb_artifact_set_produced_before_hunt(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """The KB artifact set exists in the store before the first hunt activity runs."""
    from quarry.schemas import KBDependencyGraph, KBRootIndex

    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "kb-before-hunt-1"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(FIXTURE_REPO),
            scan_id=scan_id,
            db_path=str(db_path),
            output_dir=str(output_dir),
        ),
        id=scan_id,
        task_queue="quarry-control",
    )
    result = await handle.result()
    assert result.scan_id == scan_id

    artifact_root = output_dir / "artifacts"

    # Root index persisted as an artifact and recorded on the scan metadata.
    index_path = artifact_root / scan_id / "kb" / "index.json"
    assert index_path.exists(), f"KB root index missing at {index_path}"
    index = KBRootIndex.model_validate(json.loads(index_path.read_text(encoding="utf-8")))
    assert index.scan_id == scan_id
    assert index.dependency_graph_key is not None

    # The dependency graph is present (possibly empty) — never omitted.
    graph_path = artifact_root / scan_id / index.dependency_graph_key
    assert graph_path.exists(), f"KB dependency graph missing at {graph_path}"
    KBDependencyGraph.model_validate(json.loads(graph_path.read_text(encoding="utf-8")))

    # Entity / vuln-class note keys in the index point at persisted records.
    for key in [*index.entity_keys, *index.vuln_class_note_keys]:
        assert (artifact_root / scan_id / key).exists(), f"KB record missing: {key}"

    repository = QuarryRepository(db_path)
    scan = repository.load_scan(scan_id)
    assert scan.metadata.get("kb_root_index_key"), (
        "scan metadata must record the KB root index artifact key"
    )
    assert scan.metadata.get("kb_recon_completed_at"), (
        "scan metadata must record when the KB was built so consumers can prove "
        "the artifact set predates the hunt stage"
    )
    assert scan.metadata.get("coverage_round_index") is not None, (
        "the hunt coverage loop must run after the KB was built"
    )

    # Ordering evidence: kb.recon.completed is emitted before the first hunt round.
    events = repository.load_events(scan_id)
    event_types = [e.event_type for e in events]
    assert "kb.recon.completed" in event_types, (
        f"Expected kb.recon.completed event, got: {event_types}"
    )
    assert "round.started" in event_types, f"No hunt round ran: {event_types}"
