"""Integration test: real scan of vulnerable-fastapi produces findings."""

from pathlib import Path

import pytest

from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, run_scan

REPO_ROOT = Path("examples/vulnerable-fastapi").resolve()


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
def test_real_scan_finds_hardcoded_secret(tmp_path: Path) -> None:
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    result = run_scan(
        RunScanInput(
            repo_path=str(REPO_ROOT),
            db_path=str(db_path),
            output_dir=str(output_dir),
        )
    )

    repository = QuarryRepository(db_path)
    candidates = repository.load_candidate_findings(result.scan_id)
    finals = repository.load_final_findings(result.scan_id)

    assert result.candidate_finding_count >= 1
    assert result.final_finding_count >= 1

    secret_candidates = [c for c in candidates if "ADMIN_API_KEY" in c.title]
    assert len(secret_candidates) == 1
    assert secret_candidates[0].vuln_class.value == "secrets"

    secret_finals = [f for f in finals if "ADMIN_API_KEY" in f.title]
    assert len(secret_finals) == 1
    assert secret_finals[0].severity.value == "high"

    report_path = Path(result.report_path)
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "ADMIN_API_KEY" in report_text
    assert "Final findings" in report_text
