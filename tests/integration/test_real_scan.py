"""Integration test: sync scan of vulnerable-fastapi with pure-agentic pipeline.

With the pure-agentic pivot, the sync run_scan() is a scaffold that creates the
scan record and snapshot but produces no findings (hunting happens in the Temporal
workflow path via MockModelClient). This test verifies the pipeline completes cleanly.
"""

from pathlib import Path

import pytest

from quarry_workflows import RunScanInput, run_scan

REPO_ROOT = Path("examples/vulnerable-fastapi").resolve()


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
def test_real_scan_completes_without_error(tmp_path: Path) -> None:
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    result = run_scan(
        RunScanInput(
            repo_path=str(REPO_ROOT),
            db_path=str(db_path),
            output_dir=str(output_dir),
        )
    )

    assert result.scan_id
    report_path = Path(result.report_path)
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "Quarry Scan Report" in report_text
