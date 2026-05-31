from pathlib import Path

from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, run_fake_scan


def test_fake_scan_writes_report_and_persists_candidate(tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    result = run_fake_scan(
        RunScanInput(repo_path=str(repo_path), db_path=str(db_path), output_dir=str(output_dir))
    )

    report_path = Path(result.report_path)
    repository = QuarryRepository(db_path)
    findings = repository.load_candidate_findings(result.scan_id)
    summary = repository.list_scan_summaries()[0]

    assert result.candidate_finding_count == 1
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "Fake candidate finding" in report_text
    assert "## Repository snapshot" in report_text
    assert "Frameworks: `unknown`" in report_text
    assert len(findings) == 1
    assert summary.status == "completed"
    assert summary.report_path == str(report_path)
