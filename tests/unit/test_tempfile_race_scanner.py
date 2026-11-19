"""Unit tests: tempfile_race deterministic scanner.

Covers the plugin-framework spec scenarios — predictable-tmp-name-is-detected,
deprecated-mktemp-api-is-detected, safe-tempfile-usage-is-not-flagged — plus the
binary-file skip, the repo-scan file_paths path, the CandidateFinding converter,
and the vulnerable-cli fixture sink (C8 acceptance target).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry.schemas import VulnerabilityClass
from quarry_plugins.vuln_classes.tempfile_race import (
    scan_file_for_tempfile_races,
    scan_repo_for_tempfile_races,
    tempfile_match_to_candidate_finding,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "examples" / "vulnerable-cli"
FIXTURE_MAIN = FIXTURE_ROOT / "src" / "main.rs"


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_predictable_tmp_path_is_detected(tmp_path: Path) -> None:
    """Scenario: predictable-tmp-name-is-detected."""
    path = _write(
        tmp_path,
        "app.py",
        'def save(data):\n    with open("/tmp/myapp.cache", "w") as fh:\n        fh.write(data)\n',
    )

    matches = scan_file_for_tempfile_races(path, tmp_path)

    assert [(m.line_number, m.temp_path) for m in matches] == [(2, "/tmp/myapp.cache")]
    assert matches[0].evidence_kind == "predictable_temp_path"


def test_var_tmp_predictable_path_is_detected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "worker.c",
        'FILE *f = fopen("/var/tmp/worker.lock", "w");\n',
    )

    matches = scan_file_for_tempfile_races(path, tmp_path)

    assert [m.temp_path for m in matches] == ["/var/tmp/worker.lock"]


def test_deprecated_mktemp_api_is_detected(tmp_path: Path) -> None:
    """Scenario: deprecated-mktemp-api-is-detected."""
    path = _write(
        tmp_path,
        "legacy.py",
        "import tempfile\nname = tempfile.mktemp()\n",
    )

    matches = scan_file_for_tempfile_races(path, tmp_path)

    assert [m.sink_name for m in matches] == ["tempfile.mktemp"]
    assert matches[0].evidence_kind == "deprecated_tempfile_api"


def test_bare_tmpnam_is_detected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "legacy.c",
        "char *p = tmpnam(NULL);\n",
    )

    matches = scan_file_for_tempfile_races(path, tmp_path)

    assert [m.sink_name for m in matches] == ["tmpnam"]
    assert matches[0].evidence_kind == "deprecated_tempfile_api"


def test_shell_mktemp_with_fixed_template_is_detected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "scan.sh",
        "TMP=$(mktemp /tmp/scan.$$)\n",
    )

    matches = scan_file_for_tempfile_races(path, tmp_path)

    assert [m.sink_name for m in matches] == ["mktemp"]


def test_safe_tempfile_usage_is_not_flagged(tmp_path: Path) -> None:
    """Scenario: safe-tempfile-usage-is-not-flagged."""
    path = _write(
        tmp_path,
        "safe.py",
        "import tempfile\nfd, name = tempfile.mkstemp()\nTMP=$(mktemp --tmpdir)\nTMP2=$(mktemp)\n",
    )

    assert scan_file_for_tempfile_races(path, tmp_path) == []


def test_comment_lines_are_not_flagged(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "notes.py",
        '# open("/tmp/old.cache", "w")\n// tempfile.mktemp()\n',
    )

    assert scan_file_for_tempfile_races(path, tmp_path) == []


def test_binary_file_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x00\x01\x02/tmp/predictable\x00")

    assert scan_file_for_tempfile_races(path, tmp_path) == []


def test_repo_scan_honours_file_paths_and_skips_excluded_dirs(tmp_path: Path) -> None:
    _write(tmp_path, "src/app.py", 'open("/tmp/predictable", "w")\n')
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "t.py").write_text('open("/tmp/ignored", "w")\n', encoding="utf-8")

    matches = scan_repo_for_tempfile_races(tmp_path)

    assert {m.file_path for m in matches} == {"src/app.py"}

    explicit = scan_repo_for_tempfile_races({"repo_root": str(tmp_path), "file_paths": None})
    assert {m.file_path for m in explicit} == {"src/app.py"}


def test_match_converts_to_candidate_finding(tmp_path: Path) -> None:
    path = _write(tmp_path, "app.py", 'open("/tmp/myapp.cache", "w")\n')
    matches = scan_file_for_tempfile_races(path, tmp_path)
    assert matches

    finding = tempfile_match_to_candidate_finding(matches[0], scan_id="scan-1")

    assert finding.vuln_class is VulnerabilityClass.TEMPFILE_RACE
    assert finding.scan_id == "scan-1"
    assert finding.source_refs[0].file_path == "app.py"
    assert finding.source_refs[0].start_line == 1
    assert finding.evidence_path[0].path == "app.py"
    assert finding.metadata.get("evidence_kind") == "predictable_temp_path"
    assert finding.created_by == "tempfile-race-scanner"


@pytest.mark.skipif(not FIXTURE_MAIN.exists(), reason="vulnerable-cli fixture not present")
def test_vulnerable_cli_fixture_predictable_tmp_path_is_detected() -> None:
    """C8 acceptance: the deterministic sweep flags the vulnerable-cli sink."""
    matches = scan_file_for_tempfile_races(FIXTURE_MAIN, REPO_ROOT)

    assert any(m.temp_path == "/tmp/vulnerable-cli-tmp" for m in matches)
