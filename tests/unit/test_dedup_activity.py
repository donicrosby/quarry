"""Tests for DeduplicateActivity (Week 13 / Part 1D).

Written RED first — these fail until deduplicate_activity is implemented.

Algorithm:
1. Group CandidateFindings by root_cause_key.
   - Size-1 clusters: kept unchanged, NO model call.
   - Size 2–5: agent receives cluster fingerprints, emits keep-all / keep-first /
     keep-by-index. Decision is applied.
   - Size >5: truncate to first 5 by discovery order, append a scan log warning.
2. Pure set operations (exact root_cause_key match) are deterministic.
   Only ambiguous "same root cause?" judgment is delegated to the agent.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    Severity,
    VulnerabilityClass,
)
from quarry_activities.dedup import _dedup_impl
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _DedupeResponse(BaseModel):
    """Mock response schema for the dedup agent loop."""

    decision: str = "keep_first"  # keep_all | keep_first | keep_by_index
    keep_indices: list[int] = []
    tool_calls: list[ToolCallRequest] = []


def _make_finding(
    *,
    id: str = "cf-1",
    root_cause_key: str = "key-1",
    vuln_class: VulnerabilityClass = VulnerabilityClass.COMMAND_INJECTION,
    title: str = "Unsanitized exec",
) -> CandidateFinding:
    return CandidateFinding(
        id=id,
        scan_id="scan-1",
        workspace_id="ws-1",
        vuln_class=vuln_class,
        title=title,
        hypothesis="User input reaches os.exec.",
        root_cause_key=root_cause_key,
        confidence=Confidence.MEDIUM,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDedupSingletonClusters:
    def test_single_finding_kept_unchanged(self) -> None:
        """A cluster of size 1 must be kept without any model call."""
        findings = [_make_finding(id="cf-1", root_cause_key="key-1")]

        # If a model call is made, this client will raise to surface the error
        client = MagicMock()
        client.complete_structured.side_effect = AssertionError("No model call expected for size-1 cluster")

        result = _dedup_impl(candidates=findings, client=client)

        assert len(result) == 1
        assert result[0].id == "cf-1"

    def test_multiple_distinct_keys_all_kept(self) -> None:
        """Findings with different root_cause_keys are all kept."""
        findings = [
            _make_finding(id="cf-1", root_cause_key="key-1"),
            _make_finding(id="cf-2", root_cause_key="key-2"),
            _make_finding(id="cf-3", root_cause_key="key-3"),
        ]

        # No model calls needed — each cluster is size 1
        client = MagicMock()
        client.complete_structured.side_effect = AssertionError("No model calls for all-distinct keys")

        result = _dedup_impl(candidates=findings, client=client)

        ids = {f.id for f in result}
        assert ids == {"cf-1", "cf-2", "cf-3"}


class TestDedupAgentMerge:
    def test_identical_keys_collapse_with_keep_first(self) -> None:
        """Two findings with the same root_cause_key collapse to one via 'keep_first'."""
        findings = [
            _make_finding(id="cf-1", root_cause_key="key-dup"),
            _make_finding(id="cf-2", root_cause_key="key-dup"),
        ]
        client = MockModelClient(default=_DedupeResponse(decision="keep_first"))

        result = _dedup_impl(candidates=findings, client=client)

        assert len(result) == 1
        assert result[0].id == "cf-1"

    def test_keep_all_preserves_both(self) -> None:
        """Agent decision 'keep_all' preserves both findings in the cluster."""
        findings = [
            _make_finding(id="cf-1", root_cause_key="key-dup"),
            _make_finding(id="cf-2", root_cause_key="key-dup"),
        ]
        client = MockModelClient(default=_DedupeResponse(decision="keep_all"))

        result = _dedup_impl(candidates=findings, client=client)

        assert len(result) == 2
        ids = {f.id for f in result}
        assert ids == {"cf-1", "cf-2"}

    def test_keep_by_index_selects_correct(self) -> None:
        """Agent decision 'keep_by_index' with [1] keeps the second finding."""
        findings = [
            _make_finding(id="cf-1", root_cause_key="key-dup"),
            _make_finding(id="cf-2", root_cause_key="key-dup"),
        ]
        client = MockModelClient(
            default=_DedupeResponse(decision="keep_by_index", keep_indices=[1])
        )

        result = _dedup_impl(candidates=findings, client=client)

        assert len(result) == 1
        assert result[0].id == "cf-2"

    def test_mixed_keys_partial_dedup(self) -> None:
        """Cluster with duplicate key collapses; singleton cluster is untouched."""
        findings = [
            _make_finding(id="cf-1", root_cause_key="key-dup"),
            _make_finding(id="cf-2", root_cause_key="key-dup"),
            _make_finding(id="cf-3", root_cause_key="key-unique"),
        ]
        client = MockModelClient(default=_DedupeResponse(decision="keep_first"))

        result = _dedup_impl(candidates=findings, client=client)

        ids = {f.id for f in result}
        assert "cf-1" in ids  # winner of dedup cluster
        assert "cf-3" in ids  # singleton, untouched
        assert "cf-2" not in ids  # losser of dedup cluster
        assert len(result) == 2


class TestDedupNullRootCauseKey:
    def test_findings_with_null_key_each_get_own_cluster(self) -> None:
        """Findings with root_cause_key=None should not be merged with each other."""
        findings = [
            _make_finding(id="cf-1", root_cause_key=None),  # type: ignore[arg-type]
            _make_finding(id="cf-2", root_cause_key=None),  # type: ignore[arg-type]
        ]
        # None != None in the dedup key, so each should be its own singleton
        client = MagicMock()
        client.complete_structured.side_effect = AssertionError("No model calls for null-key findings")

        result = _dedup_impl(candidates=findings, client=client)

        assert len(result) == 2


# ---------------------------------------------------------------------------
# Panel-aware client selection for deduplicate_activity (Change 3)
# ---------------------------------------------------------------------------


def test_dedup_activity_mock_panel_does_not_call_build() -> None:
    """deduplicate_activity with provider=mock must not call build_model_client."""
    from unittest.mock import patch

    from quarry.panel_config import RoleConfig
    from quarry.schemas import Provider
    from quarry_activities.dedup import deduplicate_activity

    mock_panel_json = RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30).model_dump_json()

    with patch("quarry_activities.dedup.build_model_client") as mock_build:
        deduplicate_activity([], "/tmp/repo", None, mock_panel_json)

    mock_build.assert_not_called()


def test_dedup_activity_litellm_panel_builds_litellm_client() -> None:
    """deduplicate_activity with provider=litellm must call build_model_client and pass policy."""
    from unittest.mock import MagicMock, patch

    from quarry.panel_config import RoleConfig
    from quarry.schemas import Provider
    from quarry_activities.dedup import deduplicate_activity
    from quarry_models.types import ProviderPolicy

    litellm_panel_json = RoleConfig(
        provider=Provider.LITELLM,
        model="chutes/moonshotai/Kimi-K2-Instruct",
        rpm=20,
    ).model_dump_json()

    fake_client = MagicMock()
    received_policies: list[ProviderPolicy] = []

    def _spy_loop(**kwargs: object) -> object:
        p = kwargs.get("provider_policy")
        if isinstance(p, ProviderPolicy):
            received_policies.append(p)
        from quarry.schemas import AgentLoopResult
        return AgentLoopResult(
            final_answer=None, steps=[], iterations_used=1, total_cost=0.0, stop_reason="final_answer"
        )

    # Two findings with same root_cause_key so the agent loop fires.
    findings = [
        _make_finding(id="cf-1", root_cause_key="same-key"),
        _make_finding(id="cf-2", root_cause_key="same-key"),
    ]

    with (
        patch("quarry_activities.dedup.build_model_client", return_value=fake_client) as mock_build,
        patch("quarry_activities.dedup.run_agent_loop", side_effect=_spy_loop),
    ):
        deduplicate_activity(
            [f.model_dump(mode="json") for f in findings],
            "/tmp/repo",
            None,
            litellm_panel_json,
        )

    mock_build.assert_called_once()
    assert len(received_policies) == 1
    assert received_policies[0].provider == "litellm"
    assert received_policies[0].model == "chutes/moonshotai/Kimi-K2-Instruct"
