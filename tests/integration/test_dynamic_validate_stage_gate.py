"""Integration test: dynamic_validate stage gate + prove prioritization (ADR-017).

Task 4.1 contracts for the AGENTIC dynamic-validation stage that sits between
AGENTIC_VALIDATE and PROVE:

1. With ``--dynamic-validation`` + a resolved target, the stage is ACTIVE
   (``dynamic_validation_active`` is True) — the workflow will dispatch a live
   probe and annotate the finding with a live verdict.
2. Without the flag (or without a target) the stage is a NO-OP
   (``dynamic_validation_active`` is False) — no ``http_request`` is dispatched.
3. Flag-without-target is rejected at launch (config gate + CLI guard).
4. The live verdict threads into PROVE prioritization: corroborated findings are
   proved before findings the live target defended or left inconclusive.

The workflow dispatch itself runs under Temporal; these contracts are expressed
through the pure helpers the workflow calls, so they are deterministic and
replay-safe.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    FindingStatus,
    Severity,
    SourceRef,
    VulnerabilityClass,
)
from quarry_workflows.dynamic_validate_stage import dynamic_validation_active
from quarry_workflows.prove_stage import prioritize_by_live_verdict

_NOW = datetime(2026, 6, 11, tzinfo=UTC)


def _make_candidate(
    id: str = "cf-1",
    *,
    live_verdict: str | None = None,
) -> CandidateFinding:
    metadata: dict[str, str] = {}
    if live_verdict is not None:
        metadata["live_verdict"] = live_verdict
    return CandidateFinding(
        id=id,
        scan_id="scan-dyn-1",
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.IDOR,
        title="IDOR on /users/{id}",
        hypothesis="Unauth read of another user's profile via GET /users/{id}.",
        affected_component="src/routes/users.py:42",
        root_cause_key=f"idor-{id}",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
        source_refs=[
            SourceRef(
                file_path="src/routes/users.py",
                start_line=42,
                end_line=50,
                symbol="get_user",
            )
        ],
        status=FindingStatus.NEEDS_PROOF,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Contract 1 & 2: stage gate (active only with flag + target)
# ---------------------------------------------------------------------------


class TestDynamicValidationGate:
    def test_active_with_flag_and_target(self) -> None:
        assert dynamic_validation_active(enabled=True, target_url="http://localhost:9000") is True

    def test_noop_without_flag(self) -> None:
        assert dynamic_validation_active(enabled=False, target_url="http://localhost:9000") is False

    def test_noop_without_target(self) -> None:
        assert dynamic_validation_active(enabled=True, target_url=None) is False

    def test_noop_with_empty_target(self) -> None:
        assert dynamic_validation_active(enabled=True, target_url="") is False

    def test_noop_when_neither(self) -> None:
        assert dynamic_validation_active(enabled=False, target_url=None) is False


# ---------------------------------------------------------------------------
# Contract 3: flag-without-target rejected at launch
# ---------------------------------------------------------------------------


class TestLaunchGuard:
    def test_config_gate_rejects_flag_without_target(self) -> None:
        from quarry.panel_config import resolve_dynamic
        from quarry.schemas import Target

        target = Target(
            id="target-1",
            workspace_id="local",
            repo_path="/tmp/test-repo",
            target_url=None,
            allowed_hosts=[],
            created_at=_NOW,
        )
        with pytest.raises(ValueError, match="target_url|target-url|--target"):
            resolve_dynamic(
                target=target,
                dynamic_validation_enabled=True,
                live_prove_enabled=False,
                target_authorization=None,
            )


# ---------------------------------------------------------------------------
# Contract 4: live verdict threads into PROVE prioritization
# ---------------------------------------------------------------------------


class TestProvePrioritization:
    def test_corroborated_findings_come_first(self) -> None:
        inconclusive = _make_candidate("cf-inconclusive", live_verdict="inconclusive")
        corroborated = _make_candidate("cf-corroborated", live_verdict="corroborated")
        not_corr = _make_candidate("cf-not-corr", live_verdict="not_corroborated")
        ordered = prioritize_by_live_verdict([inconclusive, not_corr, corroborated])
        assert ordered[0].id == "cf-corroborated"

    def test_stable_order_preserved_within_a_verdict_tier(self) -> None:
        a = _make_candidate("cf-a", live_verdict="inconclusive")
        b = _make_candidate("cf-b", live_verdict="inconclusive")
        ordered = prioritize_by_live_verdict([a, b])
        assert [f.id for f in ordered] == ["cf-a", "cf-b"]

    def test_unannotated_findings_are_retained(self) -> None:
        plain = _make_candidate("cf-plain")
        corroborated = _make_candidate("cf-corroborated", live_verdict="corroborated")
        ordered = prioritize_by_live_verdict([plain, corroborated])
        assert {f.id for f in ordered} == {"cf-plain", "cf-corroborated"}
        assert ordered[0].id == "cf-corroborated"

    def test_empty_list_returns_empty(self) -> None:
        assert prioritize_by_live_verdict([]) == []
