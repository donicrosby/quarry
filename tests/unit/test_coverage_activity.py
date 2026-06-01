"""Coverage ledger activity tests (direct-call and artifact persistence)."""

import json
from pathlib import Path

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    CoverageGap,
    CoverageLedger,
    VulnerabilityClass,
)
from quarry_activities.coverage import (
    build_coverage_ledger,
    build_coverage_ledger_activity,
    write_coverage_artifact,
)
from quarry_activities.inputs import BuildCoverageLedgerInput


def test_build_coverage_ledger_records_requested_and_completed() -> None:
    gaps = [
        CoverageGap(id="g1", scan_id="scan-1", attack_surface_item_id="r1", reason="not probed")
    ]
    ledger = build_coverage_ledger(
        scan_id="scan-1",
        workspace_id="local",
        requested_vuln_classes=[VulnerabilityClass.SECRETS],
        completed_vuln_classes=[VulnerabilityClass.SECRETS],
        attack_surface_items_total=3,
        attack_surface_items_scanned=0,
        skipped_items=gaps,
    )

    assert ledger.vuln_classes_requested == [VulnerabilityClass.SECRETS]
    assert ledger.vuln_classes_completed == [VulnerabilityClass.SECRETS]
    assert ledger.attack_surface_items_total == 3
    assert ledger.attack_surface_items_scanned == 0
    assert len(ledger.skipped_items) == 1
    assert ledger.skipped_items[0].attack_surface_item_id == "r1"


def test_write_coverage_artifact_writes_json(tmp_path: Path) -> None:
    ledger = build_coverage_ledger(
        scan_id="scan-1",
        workspace_id="local",
        requested_vuln_classes=[VulnerabilityClass.SECRETS],
        completed_vuln_classes=[],
        attack_surface_items_total=0,
        attack_surface_items_scanned=0,
        skipped_items=[],
    )

    ref = write_coverage_artifact(ledger, tmp_path)

    assert ref.kind is ArtifactKind.COVERAGE_LEDGER
    artifact_path = tmp_path / "scan-1" / f"coverage-{ledger.id}.json"
    assert artifact_path.exists()
    reloaded = CoverageLedger.model_validate_json(artifact_path.read_text(encoding="utf-8"))
    assert reloaded.scan_id == "scan-1"


def test_activity_builds_ledger_and_artifact(tmp_path: Path) -> None:
    skipped = [
        {
            "attack_surface_item_id": "r1",
            "vuln_class": None,
            "reason": "Mapped HTTP route not probed; secrets scanning is file-based.",
            "recommended_next_task": "Add route-level scanners.",
        }
    ]
    output = build_coverage_ledger_activity(
        BuildCoverageLedgerInput(
            scan_id="scan-1",
            workspace_id="local",
            artifact_root=str(tmp_path),
            requested_vuln_classes=("secrets",),
            completed_vuln_classes=("secrets",),
            attack_surface_items_total=2,
            attack_surface_items_scanned=0,
            skipped_json=json.dumps(skipped),
        )
    )

    ledger = CoverageLedger.model_validate_json(output.ledger_json)
    ref = ArtifactRef.model_validate_json(output.artifact_ref_json)

    assert ledger.attack_surface_items_total == 2
    assert ledger.skipped_items[0].reason.startswith("Mapped HTTP route not probed")
    assert ref.kind is ArtifactKind.COVERAGE_LEDGER
