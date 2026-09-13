"""Per-class verdict evaluators: SSTI marker + SQLi boolean-diff (tasks 1.3/1.4).

Written RED first — fails until the evaluators and their registration exist in
``src/quarry_activities/verdict_evaluators.py``.

Locked contracts:

- ``ssti_evaluator`` (registered under ``SSTI``): non-2xx → inconclusive;
  2xx + body containing the evaluated ``49`` marker → corroborated; 2xx without
  the marker (or a missing body) → not_corroborated.
- ``sql_injection_evaluator`` (registered under ``SQL_INJECTION``): no baseline
  probe → inconclusive (the differential needs the pair); primary non-2xx →
  inconclusive; either body unresolvable → inconclusive; bodies diverge →
  corroborated; identical → not_corroborated.
- Registration hygiene: both evaluators register on module import (via
  ``register_builtin_evaluators``), so SSTI/SQLi candidates route per-class.
- ``EvaluatorSpec`` metadata: ``min_probes`` tells the workflow how many probes
  a class needs (SQLi = 2, everything unregistered = 1).
"""

from __future__ import annotations

from collections.abc import Generator

import pytest

from quarry.schemas import VulnerabilityClass
from quarry_activities.verdict_evaluators import LiveProbeEvidence


@pytest.fixture(autouse=True)
def builtin_evaluators_registered() -> Generator[None, None, None]:
    """Ensure the builtin evaluators are registered regardless of test order.

    ``tests/unit/test_verdict_evaluators.py`` clears the registry around its
    own tests; re-establishing the builtins here keeps this file order-independent.
    """
    from quarry_activities.verdict_evaluators import register_builtin_evaluators

    register_builtin_evaluators()
    yield
    register_builtin_evaluators()


# Referenced so pyright's reportUnusedFunction does not fire on the fixture.
_FIXTURES = (builtin_evaluators_registered,)


# ---------------------------------------------------------------------------
# SSTI marker evaluator — every branch
# ---------------------------------------------------------------------------


class TestSstiEvaluator:
    @pytest.mark.parametrize(
        ("status_code", "body_text", "expected"),
        [
            # 2xx + evaluated marker → corroborated (marker anywhere in body).
            (200, "Hello 49!", "corroborated"),
            (200, "49", "corroborated"),
            (204, "result=49;", "corroborated"),
            (299, "x49y", "corroborated"),
            # 2xx without the marker → not_corroborated.
            (200, "[]", "not_corroborated"),
            (200, "4", "not_corroborated"),
            (200, "{{7*7}}", "not_corroborated"),  # literal echo — no evaluation
            # 2xx + missing body → not_corroborated (never corroborate on absent evidence).
            (200, None, "not_corroborated"),
            (204, None, "not_corroborated"),
            # Any non-2xx → inconclusive, even with the marker in the body.
            (500, "49", "inconclusive"),
            (404, "49", "inconclusive"),
            (302, "49", "inconclusive"),
            (199, "49", "inconclusive"),
        ],
    )
    def test_branches(self, status_code: int, body_text: str | None, expected: str) -> None:
        from quarry_activities.verdict_evaluators import ssti_evaluator

        verdict = ssti_evaluator(LiveProbeEvidence(status_code=status_code, body_text=body_text))
        assert verdict == expected

    def test_ignores_baseline_probes(self) -> None:
        """SSTI is single-probe: ``additional`` evidence never changes the verdict."""
        from quarry_activities.verdict_evaluators import ssti_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="no marker",
            additional=(LiveProbeEvidence(status_code=200, body_text="49"),),
        )
        assert ssti_evaluator(ev) == "not_corroborated"


# ---------------------------------------------------------------------------
# SQLi boolean-diff evaluator — every branch + edge cases
# ---------------------------------------------------------------------------


class TestSqlInjectionEvaluator:
    def test_diverging_pair_corroborates(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text='[{"id": 2}]',
            additional=(LiveProbeEvidence(status_code=200, body_text="[]"),),
        )
        assert sql_injection_evaluator(ev) == "corroborated"

    def test_identical_bodies_not_corroborated(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text='[{"id": 2}]',
            additional=(LiveProbeEvidence(status_code=200, body_text='[{"id": 2}]'),),
        )
        assert sql_injection_evaluator(ev) == "not_corroborated"

    def test_single_probe_inconclusive(self) -> None:
        """No baseline → the differential cannot decide, even on a 2xx body."""
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(status_code=200, body_text="rows")
        assert sql_injection_evaluator(ev) == "inconclusive"

    def test_primary_non_2xx_inconclusive(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=500,
            body_text="boom",
            additional=(LiveProbeEvidence(status_code=200, body_text="[]"),),
        )
        assert sql_injection_evaluator(ev) == "inconclusive"

    @pytest.mark.parametrize(
        ("primary_body", "baseline_body"),
        [
            (None, "[]"),
            ("[]", None),
            (None, None),
        ],
    )
    def test_unresolvable_body_inconclusive(
        self, primary_body: str | None, baseline_body: str | None
    ) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text=primary_body,
            additional=(LiveProbeEvidence(status_code=200, body_text=baseline_body),),
        )
        assert sql_injection_evaluator(ev) == "inconclusive"

    def test_empty_bodies_identical_not_corroborated(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="",
            additional=(LiveProbeEvidence(status_code=200, body_text=""),),
        )
        assert sql_injection_evaluator(ev) == "not_corroborated"

    def test_empty_vs_non_empty_diverges_corroborated(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="",
            additional=(LiveProbeEvidence(status_code=200, body_text="rows"),),
        )
        assert sql_injection_evaluator(ev) == "corroborated"

    def test_payload_echo_in_both_bodies_identical_not_corroborated(self) -> None:
        """Both probes echo the injected payload identically → no divergence."""
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        echoed = "query failed near '1 OR 1=1'"
        ev = LiveProbeEvidence(
            status_code=200,
            body_text=echoed,
            additional=(LiveProbeEvidence(status_code=200, body_text=echoed),),
        )
        assert sql_injection_evaluator(ev) == "not_corroborated"

    def test_divergence_present_in_baseline_only_still_corroborates(self) -> None:
        """The diff is symmetric: content only in the baseline still diverges.

        Honest limitation of the pure boolean diff — it cannot tell WHICH probe
        the divergence favors; the workflow records probe_count so a post-run
        audit can distinguish primary-heavy from baseline-heavy divergence.
        """
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="[]",
            additional=(LiveProbeEvidence(status_code=200, body_text="49 rows"),),
        )
        assert sql_injection_evaluator(ev) == "corroborated"

    def test_baseline_status_not_consulted(self) -> None:
        """Only the primary's status gates the verdict (per the evaluator spec)."""
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="rows",
            additional=(LiveProbeEvidence(status_code=500, body_text="error"),),
        )
        assert sql_injection_evaluator(ev) == "corroborated"

    def test_extra_probes_beyond_baseline_ignored(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="a",
            additional=(
                LiveProbeEvidence(status_code=200, body_text="a"),
                LiveProbeEvidence(status_code=200, body_text="zzz"),
            ),
        )
        assert sql_injection_evaluator(ev) == "not_corroborated"


# ---------------------------------------------------------------------------
# Registration hygiene: SSTI / SQL_INJECTION route per-class after import
# ---------------------------------------------------------------------------


class TestBuiltinRegistration:
    def test_module_import_registers_both_evaluators(self) -> None:
        """A FRESH interpreter import registers both evaluators (no reload —
        reloading would rebind the function objects and stale run_scan's
        re-exported references for other tests)."""
        import subprocess
        import sys

        code = (
            "from quarry.schemas import VulnerabilityClass\n"
            "import quarry_activities.verdict_evaluators as ve\n"
            "assert ve.resolve_evaluator(VulnerabilityClass.SSTI) is ve.ssti_evaluator\n"
            "assert ve.resolve_evaluator(VulnerabilityClass.SQL_INJECTION)"
            " is ve.sql_injection_evaluator\n"
            "print('ok')\n"
        )
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "ok"

    def test_register_builtin_evaluators_idempotent(self) -> None:
        from quarry_activities import verdict_evaluators as ve

        ve.clear_evaluators()
        ve.register_builtin_evaluators()
        ve.register_builtin_evaluators()
        assert ve.resolve_evaluator(VulnerabilityClass.SSTI) is ve.ssti_evaluator

    def test_evaluate_routes_per_class_with_source_tag(self) -> None:
        from quarry_activities.verdict_evaluators import evaluate_live_verdict_with_source

        ssti = evaluate_live_verdict_with_source(
            VulnerabilityClass.SSTI, LiveProbeEvidence(status_code=200, body_text="49")
        )
        assert ssti == ("corroborated", "per_class")

        sqli = evaluate_live_verdict_with_source(
            VulnerabilityClass.SQL_INJECTION,
            LiveProbeEvidence(
                status_code=200,
                body_text="a",
                additional=(LiveProbeEvidence(status_code=200, body_text="b"),),
            ),
        )
        assert sqli == ("corroborated", "per_class")

    def test_default_evaluator_ignores_bodies_for_unregistered_class(self) -> None:
        """Registering two classes must not change behavior for everyone else."""
        from quarry_activities.verdict_evaluators import evaluate_live_verdict_with_source

        verdict, source = evaluate_live_verdict_with_source(
            VulnerabilityClass.LDAP_INJECTION,
            LiveProbeEvidence(status_code=403, body_text="anything"),
        )
        assert (verdict, source) == ("not_corroborated", "default")


# ---------------------------------------------------------------------------
# EvaluatorSpec metadata (min_probes) — what the workflow consults
# ---------------------------------------------------------------------------


class TestEvaluatorSpecMetadata:
    def test_ssti_needs_single_probe(self) -> None:
        from quarry_activities.verdict_evaluators import resolve_evaluator_spec

        assert resolve_evaluator_spec(VulnerabilityClass.SSTI).min_probes == 1

    def test_sqli_needs_pair(self) -> None:
        from quarry_activities.verdict_evaluators import resolve_evaluator_spec

        assert resolve_evaluator_spec(VulnerabilityClass.SQL_INJECTION).min_probes == 2

    def test_unregistered_class_defaults_to_single_probe_default_fn(self) -> None:
        from quarry_activities.verdict_evaluators import (
            default_evaluator,
            resolve_evaluator_spec,
        )

        spec = resolve_evaluator_spec(VulnerabilityClass.WEAK_CRYPTO)
        assert spec.min_probes == 1
        assert spec.fn is default_evaluator

    def test_register_evaluator_accepts_min_probes(self) -> None:
        from quarry_activities.verdict_evaluators import (
            LiveProbeEvidence as Ev,
        )
        from quarry_activities.verdict_evaluators import (
            register_evaluator,
            resolve_evaluator_spec,
        )

        def sentinel(ev: Ev) -> str:
            return "inconclusive"

        register_evaluator(VulnerabilityClass.XXE, sentinel, min_probes=2)
        assert resolve_evaluator_spec(VulnerabilityClass.XXE).min_probes == 2
        assert resolve_evaluator_spec(VulnerabilityClass.XXE).fn is sentinel

    def test_resolving_fn_still_returns_the_callable(self) -> None:
        """Back-compat: resolve_evaluator keeps returning the bare function."""
        from quarry_activities.verdict_evaluators import (
            resolve_evaluator,
            ssti_evaluator,
        )

        assert resolve_evaluator(VulnerabilityClass.SSTI) is ssti_evaluator
