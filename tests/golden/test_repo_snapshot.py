import json
from pathlib import Path

from quarry_activities.repo import build_file_manifest, detect_frameworks


def test_vulnerable_fastapi_snapshot_matches_golden_fixture() -> None:
    repo_path = Path("examples/vulnerable-fastapi")
    expected = json.loads(
        Path("tests/fixtures/vulnerable-fastapi/expected_repo_snapshot.json").read_text(
            encoding="utf-8"
        )
    )

    manifest = build_file_manifest(repo_path)
    actual_entries = [
        {"path": entry.path, "language": entry.language} for entry in manifest.entries
    ]

    assert actual_entries == expected["entries"]
    assert detect_frameworks(repo_path) == expected["detected_frameworks"]
    assert all(len(entry.sha256) == 64 for entry in manifest.entries)
