"""Tests for finding fingerprint computation."""

from quarry.fingerprints import compute_fingerprint
from quarry.schemas import VulnerabilityClass


def test_fingerprint_is_stable_across_calls() -> None:
    fp1 = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="app.py",
        start_line=9,
        key_name="ADMIN_API_KEY",
        evidence_kind="hardcoded_assignment",
    )
    fp2 = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="app.py",
        start_line=9,
        key_name="ADMIN_API_KEY",
        evidence_kind="hardcoded_assignment",
    )
    assert fp1 == fp2


def test_fingerprint_changes_with_different_inputs() -> None:
    fp1 = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="app.py",
        start_line=9,
        key_name="ADMIN_API_KEY",
        evidence_kind="hardcoded_assignment",
    )
    fp2 = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="config.py",
        start_line=9,
        key_name="ADMIN_API_KEY",
        evidence_kind="hardcoded_assignment",
    )
    assert fp1 != fp2


def test_fingerprint_is_consistent_for_same_relative_path() -> None:
    """Same relative path always produces the same fingerprint."""
    fp_a = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="app.py",
        start_line=9,
        key_name="ADMIN_API_KEY",
        evidence_kind="hardcoded_assignment",
    )
    fp_b = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="app.py",
        start_line=9,
        key_name="ADMIN_API_KEY",
        evidence_kind="hardcoded_assignment",
    )
    assert fp_a == fp_b


def test_fingerprint_normalizes_backslashes() -> None:
    fp_forward = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="src/app.py",
        start_line=9,
        key_name="KEY",
        evidence_kind="hardcoded",
    )
    fp_backslash = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="src\\app.py",
        start_line=9,
        key_name="KEY",
        evidence_kind="hardcoded",
    )
    assert fp_forward == fp_backslash


def test_fingerprint_is_deterministic_hex_digest() -> None:
    fp = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="app.py",
        start_line=1,
        key_name="KEY",
        evidence_kind="test",
    )
    assert len(fp) == 64  # SHA-256 hex digest
    assert all(c in "0123456789abcdef" for c in fp)


def test_fingerprint_differs_by_vuln_class() -> None:
    fp_secrets = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="app.py",
        start_line=9,
        key_name="KEY",
        evidence_kind="hardcoded",
    )
    fp_idor = compute_fingerprint(
        vuln_class=VulnerabilityClass.IDOR,
        file_path="app.py",
        start_line=9,
        key_name="KEY",
        evidence_kind="hardcoded",
    )
    assert fp_secrets != fp_idor


def test_fingerprint_differs_by_key_name() -> None:
    fp_a = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="app.py",
        start_line=9,
        key_name="API_KEY",
        evidence_kind="hardcoded",
    )
    fp_b = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="app.py",
        start_line=9,
        key_name="SECRET_TOKEN",
        evidence_kind="hardcoded",
    )
    assert fp_a != fp_b


def test_fingerprint_differs_by_line_number() -> None:
    fp_9 = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="app.py",
        start_line=9,
        key_name="KEY",
        evidence_kind="hardcoded",
    )
    fp_10 = compute_fingerprint(
        vuln_class=VulnerabilityClass.SECRETS,
        file_path="app.py",
        start_line=10,
        key_name="KEY",
        evidence_kind="hardcoded",
    )
    assert fp_9 != fp_10
