"""Golden test: the dependency-manifest scanner pins an exact finding set.

The fixture is a two-manifest repo — an unpinned requirement, a ``git+https``
requirement with no version specifier, and an npm ``postinstall`` hook. Exactly
four ``CandidateFinding`` records (three HIGH, one MEDIUM) are expected; this is
the pinned golden set from the ``dependency-manifest-scanner`` change.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from quarry.schemas import FindingStatus, Severity, VulnerabilityClass
from quarry_activities.dependency_risk import dependency_risk_scanner_activity

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "dependency-manifest"

EXPECTED_TITLES: dict[str, Severity] = {
    "Unpinned dependency: requests": Severity.HIGH,
    "Unpinned dependency: repo": Severity.HIGH,
    "Git dependency: repo": Severity.HIGH,
    "npm install hook script: postinstall": Severity.MEDIUM,
}


def test_fixture_produces_exactly_the_pinned_finding_set() -> None:
    findings = dependency_risk_scanner_activity(str(FIXTURE_DIR), None)
    assert len(findings) == 4
    assert Counter(finding.severity for finding in findings) == Counter(
        {Severity.HIGH: 3, Severity.MEDIUM: 1}
    )
    assert {finding.title: finding.severity for finding in findings} == EXPECTED_TITLES
    assert all(finding.vuln_class is VulnerabilityClass.SUPPLY_CHAIN for finding in findings)
    assert all(finding.status is FindingStatus.CANDIDATE for finding in findings)
    for finding in findings:
        # Evidence path is sink-first and repo-relative (manifest path + line).
        assert finding.evidence_path
        assert not finding.evidence_path[0].path.startswith("/")
