"""Golden test: scanner findings on vulnerable-fastapi match expected fixture."""

import json
from pathlib import Path

import pytest

from quarry_activities.validation import validate_secret_candidate
from quarry_plugins.vuln_classes.secrets import (
    scan_repo_for_secrets,
    secret_match_to_candidate_finding,
)

FIXTURES_DIR = Path("tests/fixtures/vulnerable-fastapi")
REPO_ROOT = Path("examples/vulnerable-fastapi").resolve()
EXPECTED_PATH = FIXTURES_DIR / "expected_findings.json"


@pytest.fixture
def expected_findings() -> list[dict[str, str | int]]:
    raw = EXPECTED_PATH.read_text(encoding="utf-8")
    return json.loads(raw)


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
def test_secrets_scanner_finds_expected_secrets(expected_findings: list[dict[str, object]]) -> None:
    matches = scan_repo_for_secrets(REPO_ROOT)
    actual_by_key = {m.key_name: m for m in matches}

    for entry in expected_findings:
        key_name = str(entry["key_name"])
        assert key_name in actual_by_key, f"Expected to find secret with key name '{key_name}'"

        match = actual_by_key[key_name]
        assert match.file_path == str(entry["file_path"])
        assert match.line_number == int(str(entry["line_number"]))
        assert match.key_name == key_name


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
def test_expected_secrets_validate_successfully(
    expected_findings: list[dict[str, str | int]],
) -> None:
    matches = scan_repo_for_secrets(REPO_ROOT)
    actual_by_key = {m.key_name: m for m in matches}

    for entry in expected_findings:
        key_name = str(entry["key_name"])
        match = actual_by_key[key_name]
        finding = secret_match_to_candidate_finding(match, scan_id="golden-test-scan")
        result = validate_secret_candidate(finding)
        assert result.is_valid, f"Expected '{key_name}' to validate, got: {result.reasons}"


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
def test_expected_finding_titles_match(expected_findings: list[dict[str, str | int]]) -> None:
    matches = scan_repo_for_secrets(REPO_ROOT)
    actual_by_key = {m.key_name: m for m in matches}

    for entry in expected_findings:
        key_name = str(entry["key_name"])
        match = actual_by_key[key_name]
        finding = secret_match_to_candidate_finding(match, scan_id="golden-test-scan")
        assert finding.title == str(entry["title"])
        assert finding.vuln_class.value == str(entry["vuln_class"])
