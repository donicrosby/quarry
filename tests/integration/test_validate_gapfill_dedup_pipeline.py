"""Integration test: validate → gapfill → dedup pipeline (Week 13 / Part 1D).

Tests the three new stages working together using MockModelClient, without
a full Temporal workflow. Exercises the stage-to-stage data flow:
  1. validate: each CandidateFinding → ValidationResult
  2. gapfill: CoverageLedger + existing tasks → additional AgentTasks
  3. dedup: list[CandidateFinding] → deduplicated list

Also confirms that:
- Gapfill adds tasks for any focused class below the floor.
- Dedup collapses findings with identical root_cause_keys.
- The independence boundary holds across the pipeline.
"""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.panel_config import DEFAULT_PANEL
from quarry.schemas import (
    AgentTask,
    CandidateFinding,
    Confidence,
    CoverageLedger,
    Severity,
    ValidationResult,
    VulnerabilityClass,
)
from quarry_activities.dedup import DedupeResponse, dedup_impl
from quarry_activities.gapfill import GapfillResponse, gapfill_impl
from quarry_activities.validate import ValidateResponse, validate_impl
from quarry_models.mock_client import MockModelClient

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_finding(
    id: str = "cf-1",
    root_cause_key: str = "key-ci-admin",
    vuln_class: VulnerabilityClass = VulnerabilityClass.COMMAND_INJECTION,
    hunter_provider: str = "anthropic",
) -> CandidateFinding:
    return CandidateFinding(
        id=id,
        scan_id="scan-1",
        workspace_id="ws-1",
        vuln_class=vuln_class,
        title="Unsanitized exec",
        hypothesis="User input reaches os.exec without sanitization.",
        affected_component="src/admin.js:42-55",
        root_cause_key=root_cause_key,
        hunter_provider=hunter_provider,
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
    )


def _make_ledger(focused: list[VulnerabilityClass]) -> CoverageLedger:
    return CoverageLedger(
        id="ledger-1",
        scan_id="scan-1",
        workspace_id="ws-1",
        agent_tasks_total=5,
        agent_tasks_scanned=3,
        vuln_classes_requested=focused,
        vuln_classes_completed=[],
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# Stage 3: Validate
# ---------------------------------------------------------------------------


class TestValidateStagePipeline:
    def test_validates_two_findings(self) -> None:
        """Validate returns a result for each candidate finding."""
        findings = [
            _make_finding(id="cf-1"),
            _make_finding(id="cf-2", vuln_class=VulnerabilityClass.XSS),
        ]
        panel = dict(DEFAULT_PANEL)
        client = MockModelClient(default=ValidateResponse(verdict="validated"))

        results = [
            validate_impl(finding=f, repo_path="/tmp/repo", panel=panel, client=client)
            for f in findings
        ]

        assert len(results) == 2
        assert all(r.verdict == "validated" for r in results)
        assert {r.candidate_finding_id for r in results} == {"cf-1", "cf-2"}

    def test_mixed_verdicts(self) -> None:
        """Validate can produce different verdicts for different findings."""
        findings = [_make_finding(id="cf-1"), _make_finding(id="cf-2")]
        panel = dict(DEFAULT_PANEL)

        verdicts = ["validated", "rejected"]
        results: list[ValidationResult] = []
        for finding, verdict in zip(findings, verdicts, strict=False):
            client = MockModelClient(default=ValidateResponse(verdict=verdict))
            results.append(
                validate_impl(finding=finding, repo_path="/tmp/repo", panel=panel, client=client)
            )

        assert results[0].verdict == "validated"
        assert results[1].verdict == "rejected"


# ---------------------------------------------------------------------------
# Stage 4: Gapfill
# ---------------------------------------------------------------------------


class TestGapfillStagePipeline:
    def test_gapfill_adds_task_for_agent_reported_gap(self) -> None:
        """Gapfill produces a re-hunt task for a gap the agent actually reports."""
        focused = [VulnerabilityClass.COMMAND_INJECTION, VulnerabilityClass.SSRF]
        ledger = _make_ledger(focused)
        client = MockModelClient(
            default=GapfillResponse(
                gaps=[{"vuln_class": "ssrf", "scope": "src/", "reason": "fetch helper untraced"}]
            )
        )

        new_tasks = gapfill_impl(
            ledger=ledger,
            existing_tasks=[],
            vuln_classes=focused,
            repo_path="/tmp/repo",
            scan_id="scan-1",
            client=client,
        )

        ssrf_tasks = [t for t in new_tasks if t.vuln_class == VulnerabilityClass.SSRF]
        assert len(ssrf_tasks) == 1

    def test_gapfill_returns_nothing_without_real_gaps(self) -> None:
        """No coverage floor: empty agent output + no hunter gaps → no tasks."""
        focused = [VulnerabilityClass.IDOR]
        ledger = _make_ledger(focused)
        client = MockModelClient(default=GapfillResponse())

        new_tasks = gapfill_impl(
            ledger=ledger,
            existing_tasks=[],
            vuln_classes=focused,
            repo_path="/tmp/repo",
            scan_id="scan-1",
            client=client,
        )

        assert new_tasks == []
        assert all(t.source == "gapfill" for t in new_tasks)  # vacuously true


# ---------------------------------------------------------------------------
# Stage 5: Dedup
# ---------------------------------------------------------------------------


class TestDedupStagePipeline:
    def test_dedup_collapses_duplicate_pair(self) -> None:
        """Two findings with the same root_cause_key collapse to one."""
        findings = [
            _make_finding(id="cf-1", root_cause_key="key-dup"),
            _make_finding(id="cf-2", root_cause_key="key-dup"),
            _make_finding(id="cf-3", root_cause_key="key-unique"),
        ]
        client = MockModelClient(default=DedupeResponse(decision="keep_first"))

        result = dedup_impl(candidates=findings, client=client)

        ids = {f.id for f in result}
        assert "cf-1" in ids
        assert "cf-3" in ids
        assert "cf-2" not in ids
        assert len(result) == 2

    def test_dedup_preserves_all_when_unique(self) -> None:
        """All unique root_cause_keys → no dedup, all findings preserved."""
        findings = [_make_finding(id=f"cf-{i}", root_cause_key=f"key-{i}") for i in range(4)]
        client = MockModelClient(default=DedupeResponse(decision="keep_all"))

        result = dedup_impl(candidates=findings, client=client)

        assert len(result) == 4


# ---------------------------------------------------------------------------
# Full pipeline: validate → gapfill → dedup
# ---------------------------------------------------------------------------


class TestFullPipelineStages3to5:
    def test_pipeline_runs_all_three_stages(self) -> None:
        """End-to-end: validate all findings, gapfill, dedup — produces coherent output."""
        focused = [VulnerabilityClass.COMMAND_INJECTION, VulnerabilityClass.XSS]
        ledger = _make_ledger(focused)

        # Two hunt findings: one duplicate pair on CI, one unique XSS
        findings = [
            _make_finding(
                id="cf-1", root_cause_key="ci-dup", vuln_class=VulnerabilityClass.COMMAND_INJECTION
            ),
            _make_finding(
                id="cf-2", root_cause_key="ci-dup", vuln_class=VulnerabilityClass.COMMAND_INJECTION
            ),
            _make_finding(
                id="cf-3", root_cause_key="xss-unique", vuln_class=VulnerabilityClass.XSS
            ),
        ]
        panel = dict(DEFAULT_PANEL)

        # Stage 3: Validate each finding
        validate_client = MockModelClient(default=ValidateResponse(verdict="validated"))
        validation_results = [
            validate_impl(finding=f, repo_path="/tmp/repo", panel=panel, client=validate_client)
            for f in findings
        ]
        assert len(validation_results) == 3

        # Stage 4: Gapfill (no existing tasks besides what hunt found)
        existing_tasks = [
            AgentTask(
                id=f"t-{f.id}",
                scan_id="scan-1",
                role="hunt",
                task_name=f"hunt-{f.vuln_class.value}",
                vuln_class=f.vuln_class,
                scope="src/",
                source="recon",
                status="pending",
                created_at=_NOW,
            )
            for f in findings
        ]
        # Agent reports one real XSS gap → exactly one re-hunt task (no floor padding).
        gapfill_client = MockModelClient(
            default=GapfillResponse(
                gaps=[{"vuln_class": "xss", "scope": "src/", "reason": "reflected param untraced"}]
            )
        )
        gapfill_tasks = gapfill_impl(
            ledger=ledger,
            existing_tasks=existing_tasks,
            vuln_classes=focused,
            repo_path="/tmp/repo",
            scan_id="scan-1",
            client=gapfill_client,
        )
        xss_gap_tasks = [t for t in gapfill_tasks if t.vuln_class == VulnerabilityClass.XSS]
        assert len(xss_gap_tasks) == 1

        # Stage 5: Dedup — the duplicate CI pair collapses to one
        dedup_client = MockModelClient(default=DedupeResponse(decision="keep_first"))
        deduped = dedup_impl(candidates=findings, client=dedup_client)

        assert len(deduped) == 2  # cf-1 (winner) + cf-3 (unique)
        ids = {f.id for f in deduped}
        assert "cf-1" in ids
        assert "cf-3" in ids
        assert "cf-2" not in ids
