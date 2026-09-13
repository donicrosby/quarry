"""Differential probe dispatch: two-spec selection + workflow gating (task 1.4b).

Written RED first — fails until ``select_dynamic_probe_specs``,
``build_dynamic_probe_spec_pair`` and ``differential_baseline_permitted`` exist
in ``src/quarry_workflows/run_scan.py``.

Locked contracts:

- ``select_dynamic_probe_specs`` returns up to TWO well-formed proposals, capped
  by the class's ``min_probes`` (registry metadata): SQLi gets the agent's pair
  (or a deterministic TRUE/FALSE fallback), single-probe classes get exactly one.
- ``select_dynamic_probe_spec`` (legacy single-spec API) is unchanged: it
  delegates and returns the first spec — old callers untouched.
- Malformed proposals are skipped, never fatal.
- ``differential_baseline_permitted`` is the pure cost guard: the baseline
  probe is dispatched only when the class needs a pair AND budget remains
  (``remaining is None`` means uncapped → allowed; ``<= 0`` → refused).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    FindingStatus,
    Severity,
    SourceRef,
    VulnerabilityClass,
)
from quarry_workflows.run_scan import (
    build_dynamic_probe_spec,
    differential_baseline_permitted,
    select_dynamic_probe_spec,
    select_dynamic_probe_specs,
)

_NOW = datetime(2026, 6, 13, tzinfo=UTC)


def _make_candidate(
    vuln_class: VulnerabilityClass = VulnerabilityClass.SQL_INJECTION,
) -> CandidateFinding:
    return CandidateFinding(
        id="cf-pdv-1",
        scan_id="scan-pdv",
        workspace_id="ws-1",
        vuln_class=vuln_class,
        title="SQLi on /items",
        hypothesis="Unsanitised id reaches the WHERE clause.",
        affected_component="src/routes/items.py:31",
        root_cause_key="sqli-items-id",
        hunter_provider="mock",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
        source_refs=[
            SourceRef(
                file_path="src/routes/items.py",
                start_line=31,
                end_line=31,
                symbol="get_item",
            )
        ],
        status=FindingStatus.NEEDS_PROOF,
    )


# ---------------------------------------------------------------------------
# select_dynamic_probe_specs — pair selection
# ---------------------------------------------------------------------------


class TestSelectDynamicProbeSpecs:
    def test_sqli_agent_proposed_pair_both_selected(self) -> None:
        specs = select_dynamic_probe_specs(
            [
                {"method": "GET", "path": "/items?id=1%20OR%201%3D1"},
                {"method": "GET", "path": "/items?id=1%20AND%201%3D2"},
            ],
            _make_candidate(VulnerabilityClass.SQL_INJECTION),
        )
        assert len(specs) == 2
        assert specs[0].path == "/items?id=1%20OR%201%3D1"
        assert specs[1].path == "/items?id=1%20AND%201%3D2"

    def test_sqli_single_proposal_falls_back_to_deterministic_pair(self) -> None:
        """One usable proposal → primary is the proposal, baseline is built."""
        specs = select_dynamic_probe_specs(
            [{"method": "GET", "path": "/items?id=1%20OR%201%3D1"}],
            _make_candidate(VulnerabilityClass.SQL_INJECTION),
        )
        assert len(specs) == 2
        assert specs[0].path == "/items?id=1%20OR%201%3D1"
        assert "1%3D2" in specs[1].path  # deterministic FALSE baseline (URL-encoded)

    def test_sqli_no_proposals_deterministic_true_false_pair(self) -> None:
        specs = select_dynamic_probe_specs([], _make_candidate(VulnerabilityClass.SQL_INJECTION))
        assert len(specs) == 2
        assert specs[0].method == "GET"
        assert "OR%201%3D1" in specs[0].path  # TRUE (URL-encoded)
        assert "AND%201%3D2" in specs[1].path  # FALSE (URL-encoded)
        assert specs[0].path != specs[1].path

    def test_single_probe_class_gets_exactly_one_spec(self) -> None:
        """IDOR (min_probes=1) keeps today's behavior even with two proposals."""
        specs = select_dynamic_probe_specs(
            [
                {"method": "GET", "path": "/users/1"},
                {"method": "GET", "path": "/users/2"},
            ],
            _make_candidate(VulnerabilityClass.IDOR),
        )
        assert len(specs) == 1
        assert specs[0].path == "/users/1"

    def test_single_probe_class_falls_back_to_deterministic_spec(self) -> None:
        specs = select_dynamic_probe_specs(
            [], _make_candidate(VulnerabilityClass.COMMAND_INJECTION)
        )
        assert len(specs) == 1
        assert specs[0].path == "/debug/ping?host=127.0.0.1"

    def test_malformed_proposals_skipped(self) -> None:
        bad: list[Any] = [
            "not-a-dict",
            {"method": "GET"},  # missing path
            {"path": "/x"},  # missing method
            {"method": "TRACE", "path": "/x"},  # invalid method
        ]
        specs = select_dynamic_probe_specs(
            bad + [{"method": "GET", "path": "/items?id=1%20OR%201%3D1"}],
            _make_candidate(VulnerabilityClass.SQL_INJECTION),
        )
        assert len(specs) == 2
        assert specs[0].path == "/items?id=1%20OR%201%3D1"

    def test_secrets_returns_empty(self) -> None:
        """No probe possible → empty list (same semantics as build → None)."""
        specs = select_dynamic_probe_specs([], _make_candidate(VulnerabilityClass.SECRETS))
        assert specs == []

    def test_specs_carry_no_inline_auth(self) -> None:
        specs = select_dynamic_probe_specs([], _make_candidate(VulnerabilityClass.SQL_INJECTION))
        for spec in specs:
            assert spec.auth_profile is None


# ---------------------------------------------------------------------------
# Legacy single-spec API unchanged
# ---------------------------------------------------------------------------


class TestSelectDynamicProbeSpecLegacy:
    def test_returns_first_spec_only(self) -> None:
        spec = select_dynamic_probe_spec(
            [
                {"method": "GET", "path": "/items?id=1%20OR%201%3D1"},
                {"method": "GET", "path": "/items?id=1%20AND%201%3D2"},
            ],
            _make_candidate(VulnerabilityClass.SQL_INJECTION),
        )
        assert spec is not None
        assert spec.path == "/items?id=1%20OR%201%3D1"

    def test_deterministic_fallback_unchanged(self) -> None:
        spec = select_dynamic_probe_spec([], _make_candidate(VulnerabilityClass.IDOR))
        assert spec is not None
        assert spec.path == "/users/1"

    def test_build_dynamic_probe_spec_unchanged(self) -> None:
        assert build_dynamic_probe_spec(_make_candidate(VulnerabilityClass.SECRETS)) is None
        spec = build_dynamic_probe_spec(_make_candidate(VulnerabilityClass.IDOR))
        assert spec is not None
        assert spec.path == "/users/1"


# ---------------------------------------------------------------------------
# build_dynamic_probe_spec_pair (deterministic fallback)
# ---------------------------------------------------------------------------


class TestBuildDynamicProbeSpecPair:
    def test_sqli_pair_true_false(self) -> None:
        from quarry_workflows.run_scan import build_dynamic_probe_spec_pair

        pair = build_dynamic_probe_spec_pair(_make_candidate(VulnerabilityClass.SQL_INJECTION))
        assert pair is not None
        assert len(pair) == 2
        true_spec, false_spec = pair
        assert "OR%201%3D1" in true_spec.path
        assert "AND%201%3D2" in false_spec.path
        assert true_spec.method == "GET" == false_spec.method

    def test_non_sqli_class_returns_none(self) -> None:
        from quarry_workflows.run_scan import build_dynamic_probe_spec_pair

        assert build_dynamic_probe_spec_pair(_make_candidate(VulnerabilityClass.IDOR)) is None
        assert build_dynamic_probe_spec_pair(_make_candidate(VulnerabilityClass.SECRETS)) is None


# ---------------------------------------------------------------------------
# differential_baseline_permitted — pure cost guard
# ---------------------------------------------------------------------------


class TestDifferentialBaselinePermitted:
    def test_sqli_with_uncapped_budget_allowed(self) -> None:
        assert (
            differential_baseline_permitted(VulnerabilityClass.SQL_INJECTION, budget_remaining=None)
            is True
        )

    def test_sqli_with_positive_budget_allowed(self) -> None:
        assert (
            differential_baseline_permitted(VulnerabilityClass.SQL_INJECTION, budget_remaining=0.01)
            is True
        )

    def test_sqli_with_zero_budget_refused(self) -> None:
        assert (
            differential_baseline_permitted(VulnerabilityClass.SQL_INJECTION, budget_remaining=0.0)
            is False
        )

    def test_sqli_with_negative_budget_refused(self) -> None:
        assert (
            differential_baseline_permitted(VulnerabilityClass.SQL_INJECTION, budget_remaining=-1.0)
            is False
        )

    def test_single_probe_class_never_dispatches_baseline(self) -> None:
        for vuln_class in (VulnerabilityClass.SSTI, VulnerabilityClass.IDOR):
            assert differential_baseline_permitted(vuln_class, budget_remaining=None) is False
