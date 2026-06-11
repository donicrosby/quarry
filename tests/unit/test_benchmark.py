"""Benchmark comparison logic tests."""

from pathlib import Path

from quarry.benchmark import compare, load_ground_truth
from quarry.schemas import (
    FinalFinding,
    GroundTruthFinding,
    Severity,
    SourceRef,
    VulnerabilityClass,
    utc_now,
)

GROUND_TRUTH_PATH = Path("tests/golden/ground_truth/vulnerable-fastapi.json")


def _secret_finding() -> FinalFinding:
    return FinalFinding(
        id="1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="fp",
        vuln_class=VulnerabilityClass.SECRETS,
        severity=Severity.HIGH,
        title="Hardcoded secret",
        summary="x",
        affected_component="app.py",
        source_refs=[SourceRef(file_path="app.py", start_line=9)],
        validation_result_id="v1",
        created_at=utc_now(),
    )


def _truth() -> list[GroundTruthFinding]:
    return [
        GroundTruthFinding(
            id="gt-secret",
            vuln_class=VulnerabilityClass.SECRETS,
            file_path="app.py",
            severity=Severity.HIGH,
        ),
        GroundTruthFinding(
            id="gt-idor",
            vuln_class=VulnerabilityClass.IDOR,
            file_path="app.py",
            route="/users/{user_id}",
            severity=Severity.HIGH,
        ),
    ]


def test_compare_matches_and_misses() -> None:
    result = compare([_secret_finding()], _truth(), runtime_seconds=2.0)

    assert result.expected == 2
    assert result.matched == ["secrets:app.py"]
    assert result.missed == ["idor:app.py"]
    assert result.false_positives == []
    assert result.proof_rate == 0.0
    assert result.runtime_seconds == 2.0


def test_compare_flags_false_positive() -> None:
    bogus = _secret_finding().model_copy(update={"vuln_class": VulnerabilityClass.XSS, "id": "2"})
    result = compare([_secret_finding(), bogus], _truth())

    assert "xss:app.py" in result.false_positives
    assert "secrets:app.py" in result.matched


def test_compare_proof_rate_counts_proven_findings() -> None:
    proven = _secret_finding().model_copy(update={"proof_artifact_ids": ["proof-1"]})
    result = compare([proven], _truth())

    assert result.proof_rate == 1.0


def test_load_ground_truth_reads_demo_file() -> None:
    truth = load_ground_truth(GROUND_TRUTH_PATH)

    classes = {item.vuln_class for item in truth}
    assert VulnerabilityClass.SECRETS in classes
    assert VulnerabilityClass.IDOR in classes
    assert VulnerabilityClass.COMMAND_INJECTION in classes


def test_idor_found() -> None:
    """Verify IDOR vulnerability is detected when scanner finds it."""
    idor_finding = FinalFinding(
        id="idor-1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="idor-fp",
        vuln_class=VulnerabilityClass.IDOR,
        severity=Severity.HIGH,
        title="Potential IDOR via user_id",
        summary="Route /users/{user_id} lacks auth check",
        affected_component="app.py",
        source_refs=[SourceRef(file_path="app.py", start_line=50)],
        validation_result_id="v-idor",
        created_at=utc_now(),
    )
    truth = load_ground_truth(GROUND_TRUTH_PATH)
    result = compare([idor_finding], truth, runtime_seconds=1.0)

    assert "idor:app.py" in result.matched
    assert result.expected >= 4  # secrets, idor, command_injection, ssrf


def test_ground_truth_inside_repo_is_detected() -> None:
    """The benchmark guard flags an answer key sitting inside the scanned repo."""
    from quarry_cli.main import ground_truth_is_inside_repo

    # Inside the repo tree → cheat condition.
    assert (
        ground_truth_is_inside_repo(
            "examples/vulnerable-fastapi", "examples/vulnerable-fastapi/ground_truth.json"
        )
        is True
    )
    # Outside the repo tree (current layout) → fine.
    assert (
        ground_truth_is_inside_repo(
            "examples/vulnerable-fastapi", "tests/golden/ground_truth/vulnerable-fastapi.json"
        )
        is False
    )
