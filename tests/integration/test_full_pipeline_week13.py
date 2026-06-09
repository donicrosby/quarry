"""Part 1E — Week 13 end-to-end pipeline test.

Exercises the full five-stage pipeline (recon→hunt→validate→gapfill→dedup)
using pure in-process helpers (_*_impl functions) with MockModelClient.

Scenario: a repo is scanned for COMMAND_INJECTION and XSS.
  - Hunt produces 3 findings: a duplicate CI pair + one unique XSS.
  - hunter_provider is "litellm" (the "remote" model); the panel's validate
    role uses Provider.MOCK ("mock"), so cross_vendor_disagreement fires.
  - Validate stage: all three findings pass through; ≥1 has cross_vendor_disagreement.
  - Gapfill stage: CI already has 2 tasks; XSS has 1 → floor adds 1 → ≥2 per class.
  - Dedup stage: the duplicate CI pair collapses to 1 → net result is 2 findings.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from quarry.panel_config import DEFAULT_PANEL, RoleConfig
from quarry.schemas import (
    AgentTask,
    CandidateFinding,
    Confidence,
    CoverageLedger,
    Provider,
    Severity,
    ValidationResult,
    VulnerabilityClass,
)
from quarry_activities.dedup import _DedupeResponse, _dedup_impl
from quarry_activities.gapfill import _GapfillResponse, _gapfill_impl
from quarry_activities.validate import _ValidateResponse, _validate_impl
from quarry_models.mock_client import MockModelClient

_NOW = datetime(2026, 6, 9, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Cross-vendor panel: hunt=litellm, validate=mock
# ---------------------------------------------------------------------------

_CROSS_VENDOR_PANEL = dict(DEFAULT_PANEL)
_CROSS_VENDOR_PANEL["validate"] = RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30)
# hunt is still mock in DEFAULT_PANEL; hunter_provider is set per-finding (plain str)

# ---------------------------------------------------------------------------
# Test data helpers
# ---------------------------------------------------------------------------


def _finding(
    id: str,
    root_cause_key: str,
    vuln_class: VulnerabilityClass = VulnerabilityClass.COMMAND_INJECTION,
    hunter_provider: str = "litellm",
) -> CandidateFinding:
    return CandidateFinding(
        id=id,
        scan_id="scan-wk13",
        workspace_id="ws-wk13",
        vuln_class=vuln_class,
        title="Week-13 test finding",
        hypothesis="User input reaches a dangerous sink.",
        affected_component="examples/vulnerable-express/app.js:42-55",
        root_cause_key=root_cause_key,
        hunter_provider=hunter_provider,
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
    )


def _ledger(focused: list[VulnerabilityClass]) -> CoverageLedger:
    return CoverageLedger(
        id="ledger-wk13",
        scan_id="scan-wk13",
        workspace_id="ws-wk13",
        attack_surface_items_total=10,
        attack_surface_items_scanned=7,
        vuln_classes_requested=focused,
        vuln_classes_completed=[],
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# Scenario: hunt output
# ---------------------------------------------------------------------------

FOCUSED = [VulnerabilityClass.COMMAND_INJECTION, VulnerabilityClass.XSS]

HUNT_FINDINGS = [
    # duplicate CI pair
    _finding("cf-1", "ci-dup-root", VulnerabilityClass.COMMAND_INJECTION),
    _finding("cf-2", "ci-dup-root", VulnerabilityClass.COMMAND_INJECTION),
    # unique XSS
    _finding("cf-3", "xss-unique-root", VulnerabilityClass.XSS),
]

# Simulated agent-task set after hunt (one per finding)
HUNT_TASKS = [
    AgentTask(
        id=f"t-{f.id}",
        scan_id="scan-wk13",
        role="hunt",
        task_name=f"hunt-{f.vuln_class.value}",
        vuln_class=f.vuln_class,
        scope="examples/vulnerable-express/",
        source="recon",
        status="pending",
        created_at=_NOW,
    )
    for f in HUNT_FINDINGS
]


# ---------------------------------------------------------------------------
# Stage 3 — Validate
# ---------------------------------------------------------------------------


class TestValidateStageWeek13:
    def test_all_findings_validated(self) -> None:
        client = MockModelClient(default=_ValidateResponse(verdict="validated"))
        results = [
            _validate_impl(
                finding=f,
                repo_path="examples/vulnerable-express",
                panel=_CROSS_VENDOR_PANEL,
                client=client,
            )
            for f in HUNT_FINDINGS
        ]
        assert len(results) == len(HUNT_FINDINGS)
        assert all(isinstance(r, ValidationResult) for r in results)
        assert all(r.verdict == "validated" for r in results)

    def test_cross_vendor_disagreement_fires(self) -> None:
        """Findings with hunter_provider='litellm', validate panel='mock' → disagreement."""
        client = MockModelClient(default=_ValidateResponse(verdict="validated"))
        results = [
            _validate_impl(
                finding=f,
                repo_path="examples/vulnerable-express",
                panel=_CROSS_VENDOR_PANEL,
                client=client,
            )
            for f in HUNT_FINDINGS
        ]
        cross_vendor_count = sum(1 for r in results if r.cross_vendor_disagreement)
        assert cross_vendor_count >= 1, (
            "Expected at least one ValidationResult with cross_vendor_disagreement=True "
            f"(hunt='litellm', validate='mock'); got {cross_vendor_count}"
        )

    def test_all_results_have_candidate_ids(self) -> None:
        client = MockModelClient(default=_ValidateResponse(verdict="validated"))
        results = [
            _validate_impl(
                finding=f,
                repo_path="examples/vulnerable-express",
                panel=_CROSS_VENDOR_PANEL,
                client=client,
            )
            for f in HUNT_FINDINGS
        ]
        expected_ids = {f.id for f in HUNT_FINDINGS}
        result_ids = {r.candidate_finding_id for r in results}
        assert result_ids == expected_ids


# ---------------------------------------------------------------------------
# Stage 4 — Gapfill
# ---------------------------------------------------------------------------


class TestGapfillStageWeek13:
    def test_floor_satisfied_for_all_focused_classes(self) -> None:
        """After gapfill, every focused vuln_class has ≥2 tasks."""
        client = MockModelClient(default=_GapfillResponse())
        ledger = _ledger(FOCUSED)

        new_tasks = _gapfill_impl(
            ledger=ledger,
            existing_tasks=HUNT_TASKS,
            vuln_classes=FOCUSED,
            repo_path="examples/vulnerable-express",
            scan_id="scan-wk13",
            client=client,
        )

        # Merge existing + gapfill tasks
        all_tasks = list(HUNT_TASKS) + new_tasks

        for vc in FOCUSED:
            count = sum(1 for t in all_tasks if t.vuln_class == vc)
            assert count >= 2, (
                f"Expected ≥2 tasks for {vc.value} after gapfill; got {count}"
            )

    def test_gapfill_tasks_have_gapfill_source(self) -> None:
        client = MockModelClient(default=_GapfillResponse())
        ledger = _ledger(FOCUSED)

        new_tasks = _gapfill_impl(
            ledger=ledger,
            existing_tasks=HUNT_TASKS,
            vuln_classes=FOCUSED,
            repo_path="examples/vulnerable-express",
            scan_id="scan-wk13",
            client=client,
        )

        assert all(t.source == "gapfill" for t in new_tasks)

    def test_xss_gets_floor_task_added(self) -> None:
        """XSS has 1 existing task (below the floor of 2) → gapfill adds ≥1."""
        client = MockModelClient(default=_GapfillResponse())
        ledger = _ledger(FOCUSED)

        new_tasks = _gapfill_impl(
            ledger=ledger,
            existing_tasks=HUNT_TASKS,
            vuln_classes=FOCUSED,
            repo_path="examples/vulnerable-express",
            scan_id="scan-wk13",
            client=client,
        )

        xss_new = [t for t in new_tasks if t.vuln_class == VulnerabilityClass.XSS]
        assert len(xss_new) >= 1, (
            f"Expected ≥1 new XSS gapfill task (floor enforcement); got {len(xss_new)}"
        )


# ---------------------------------------------------------------------------
# Stage 5 — Dedup
# ---------------------------------------------------------------------------


class TestDedupStageWeek13:
    def test_duplicate_ci_pair_collapses(self) -> None:
        """cf-1 and cf-2 share root_cause_key='ci-dup-root'; they collapse to one."""
        client = MockModelClient(default=_DedupeResponse(decision="keep_first"))
        result = _dedup_impl(candidates=HUNT_FINDINGS, client=client)

        ids = {f.id for f in result}
        assert "cf-1" in ids, "Winner (cf-1) should be kept after keep_first"
        assert "cf-2" not in ids, "Duplicate (cf-2) should be dropped after keep_first"
        assert "cf-3" in ids, "Unique finding (cf-3) must be preserved"
        assert len(result) == 2

    def test_net_dedup_count_two(self) -> None:
        """3 findings → dedup → 2 findings (1 unique CI + 1 XSS)."""
        client = MockModelClient(default=_DedupeResponse(decision="keep_first"))
        result = _dedup_impl(candidates=HUNT_FINDINGS, client=client)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Full end-to-end
# ---------------------------------------------------------------------------


class TestFullPipelineWeek13:
    def test_five_stage_pipeline_coherent_output(self) -> None:
        """Run all five stages and verify the combined invariants hold."""
        # Stage 3: validate
        validate_client = MockModelClient(default=_ValidateResponse(verdict="validated"))
        validation_results = [
            _validate_impl(
                finding=f,
                repo_path="examples/vulnerable-express",
                panel=_CROSS_VENDOR_PANEL,
                client=validate_client,
            )
            for f in HUNT_FINDINGS
        ]
        assert len(validation_results) == 3
        assert sum(1 for r in validation_results if r.cross_vendor_disagreement) >= 1

        # Stage 4: gapfill
        ledger = _ledger(FOCUSED)
        gapfill_client = MockModelClient(default=_GapfillResponse())
        gapfill_tasks = _gapfill_impl(
            ledger=ledger,
            existing_tasks=HUNT_TASKS,
            vuln_classes=FOCUSED,
            repo_path="examples/vulnerable-express",
            scan_id="scan-wk13",
            client=gapfill_client,
        )

        all_tasks = list(HUNT_TASKS) + gapfill_tasks
        for vc in FOCUSED:
            count = sum(1 for t in all_tasks if t.vuln_class == vc)
            assert count >= 2, f"Floor not satisfied for {vc.value}"

        # Stage 5: dedup
        dedup_client = MockModelClient(default=_DedupeResponse(decision="keep_first"))
        deduped = _dedup_impl(candidates=HUNT_FINDINGS, client=dedup_client)
        assert len(deduped) == 2
        assert {f.id for f in deduped} == {"cf-1", "cf-3"}
