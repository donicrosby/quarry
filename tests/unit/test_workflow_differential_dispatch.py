"""Workflow wiring: differential two-probe dispatch in run_scan (task 1.4b).

Written RED first.  The workflow body runs under Temporal's sandbox, so the
repo's established pattern (see tests/unit/test_verdict_evaluators.py
``TestRunScanWiring``) is source-level contract assertions plus pure-helper
tests — with the REAL dispatch exercised in the golden test
``tests/golden/test_sqli_differential_probe.py`` against the mocked
httpx transport.

Locked contracts:

- The workflow selects specs via ``select_dynamic_probe_specs`` (plural) — a
  differential class gets TWO dispatched ``http-request`` activities.
- The baseline probe is gated by ``differential_baseline_permitted`` (pure cost
  guard) — never dispatched for single-probe classes or exhausted budget.
- Both bodies resolve via the ``read-artifact-text`` activity; the baseline is
  nested into ``LiveProbeEvidence.additional``; the verdict comes from
  ``evaluate_live_verdict_with_source`` (per-class registry).
- The ``finding.dynamic_validated`` event payload records ``probe_count``.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_SCAN = REPO_ROOT / "src" / "quarry_workflows" / "run_scan.py"


def _source() -> str:
    return _RUN_SCAN.read_text(encoding="utf-8")


class TestWorkflowDifferentialWiring:
    def test_workflow_uses_plural_spec_selection(self) -> None:
        source = _source()
        assert "select_dynamic_probe_specs(" in source, (
            "the dynamic-validate dispatch must select up to two specs "
            "(differential pair) via select_dynamic_probe_specs"
        )
        # The legacy singular helper must remain for the live-prove callers.
        assert "build_dynamic_probe_spec(candidate)" in source

    def test_baseline_dispatch_gated_by_cost_guard(self) -> None:
        source = _source()
        assert "differential_baseline_permitted(" in source, (
            "the second (baseline) probe must be gated by the pure cost guard"
        )

    def test_baseline_nested_into_additional_evidence(self) -> None:
        source = _source()
        assert "additional=" in source, (
            "the baseline capture must be nested into LiveProbeEvidence.additional"
        )

    def test_event_payload_records_probe_count(self) -> None:
        source = _source()
        assert '"probe_count"' in source, (
            "finding.dynamic_validated must record probe_count so post-run audits "
            "can see differential dispatches"
        )

    def test_second_probe_uses_single_attempt_retry_policy(self) -> None:
        """Both probes are single-attempt http-request dispatches (no retries)."""
        source = _source()
        assert source.count("RetryPolicy(maximum_attempts=1)") >= 3, (
            "dynamic-validate probes (primary + baseline) must each be "
            "single-attempt http-request activities"
        )

    def test_budget_guard_uses_val_budget_remaining(self) -> None:
        source = _source()
        assert "budget_remaining=val_budget_remaining" in source, (
            "the cost guard must consult the stage's remaining validation budget"
        )


class TestNestedEvidenceConstruction:
    def test_baseline_evidence_builds_nested_structure(self) -> None:
        """The pure nesting helper assembles the differential evidence shape."""
        from quarry.schemas import VulnerabilityClass
        from quarry_activities.verdict_evaluators import (
            LiveProbeEvidence,
            resolve_evaluator,
        )
        from quarry_workflows.run_scan import build_differential_evidence

        primary = LiveProbeEvidence(status_code=200, body_text='[{"id": 1}]')
        baseline = LiveProbeEvidence(status_code=200, body_text="[]")
        ev = build_differential_evidence(primary=primary, baseline=baseline)
        assert ev.status_code == 200
        assert ev.body_text == '[{"id": 1}]'
        assert ev.additional == (baseline,)
        # And the per-class evaluator decides on the nested pair.
        assert resolve_evaluator(VulnerabilityClass.SQL_INJECTION)(ev) == "corroborated"

    def test_primary_only_when_baseline_absent(self) -> None:
        from quarry_activities.verdict_evaluators import LiveProbeEvidence
        from quarry_workflows.run_scan import build_differential_evidence

        primary = LiveProbeEvidence(status_code=200, body_text="rows")
        ev = build_differential_evidence(primary=primary, baseline=None)
        assert ev is primary or (ev.status_code, ev.body_text, ev.additional) == (
            primary.status_code,
            primary.body_text,
            (),
        )


class TestTimingProbeDispatch:
    """Timing-oracle dispatch wiring (verify-oracle-upgrade tasks 8/9).

    The timing dispatch loop and its sub-budget run under Temporal's sandbox, so
    — like the differential wiring above — these lock the pure helpers plus the
    source-level contracts of ``run_scan``.
    """

    def test_timing_budget_gate_requires_full_ladder_batch(self) -> None:
        from quarry_workflows.run_scan import timing_ladder_permitted

        assert timing_ladder_permitted(timing_probes_remaining=3)
        assert timing_ladder_permitted(timing_probes_remaining=4)
        assert not timing_ladder_permitted(timing_probes_remaining=2)
        assert not timing_ladder_permitted(timing_probes_remaining=0)

    def test_timing_budget_counter_and_configurable_limit_wired(self) -> None:
        source = _source()
        assert "timing_probes_remaining = scan_input.dynamic_timing_probe_limit" in source
        assert "dynamic_timing_probe_limit: int = 20" in source
        # One decrement per dispatch site: baseline loop, attack loop, ladder loop.
        assert source.count("timing_probes_remaining -= 1") >= 3

    def test_timing_budget_exhausted_records_reason(self) -> None:
        source = _source()
        assert 'reason="budget_exhausted"' in source, (
            "a statistical pass without ladder headroom (or a batch cut short) "
            "must record LIVE_INCONCLUSIVE with reason budget_exhausted"
        )
        assert "timing_ladder_permitted(" in source
        assert "TIMING_STATISTICAL_PASS" in source

    def test_timing_probes_use_the_guarded_egress_funnel(self) -> None:
        source = _source()
        assert "async def _dispatch_timing_probe(" in source
        # Every timing dispatch goes through the single guarded funnel.
        assert "await _dispatch_dynamic_probe(" in source
        assert "timing_delay_for_specs(" in source

    def test_timing_dispatch_selector_needs_clean_baseline(self) -> None:
        from quarry.schemas import HttpRequestSpec, VulnerabilityClass
        from quarry_workflows.run_scan import timing_delay_for_specs

        attack = HttpRequestSpec(method="GET", path="/items?id=1", injected_delay_ms=800)
        clean = HttpRequestSpec(method="GET", path="/items?id=1")
        assert timing_delay_for_specs(VulnerabilityClass.SQL_INJECTION, [attack, clean]) == 800
        # A delay-annotated spec is never its own baseline.
        assert timing_delay_for_specs(VulnerabilityClass.SQL_INJECTION, [attack]) is None
        # A class without the timing profile never takes the timing path.
        assert timing_delay_for_specs(VulnerabilityClass.SSRF, [attack, clean]) is None
