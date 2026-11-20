"""Per-class verdict-evaluator registry (per-class-dynamic-validation tasks 1.1/1.2).

Written RED first — fails until ``src/quarry_activities/verdict_evaluators.py``
exists.

Locked contracts:

- ``LiveProbeEvidence``: resolved status + body TEXT (never raw refs) + optional
  differential probes; constructible from status alone (body/probes default off).
- ``register_evaluator`` / ``resolve_evaluator`` round-trip; unregistered classes
  fall back to the default status-only evaluator (``live_verdict_from_status``
  semantics: 2xx corroborated, 401/403/404 not_corroborated, else inconclusive).
- ``evaluate_live_verdict`` dispatches per-class; the default evaluator IGNORES
  body/additional evidence (status-only).
- Verdict provenance: ``evaluate_live_verdict_with_source`` tags per_class/default.
- Vocabulary single-sourcing: run_scan re-exports the canonical constants and
  function (dynamic_validate_stage imports them from run_scan — unchanged).
- ``resolve_live_verdict`` routes provided evidence through the registry and
  keeps the status-only behavior when evidence is absent (existing callers
  untouched — their tests stay green without modification).
- run_scan wiring: the workflow's dynamic_validate block resolves the body via
  the read-artifact-text activity and evaluates through the registry, recording
  verdict_source on the finding.dynamic_validated event.
"""

from __future__ import annotations

from collections.abc import Generator, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    HttpResponseCapture,
    RedactionStatus,
    Severity,
    SourceRef,
    VulnerabilityClass,
)

# Private pure helpers under direct test (verify-oracle-upgrade). The spec names
# them with a leading underscore; the repo's precedent for exercising a private
# helper from tests is a localised type: ignore on the import line (see
# tests/unit/test_retry_config_plumbing.py).
from quarry_activities.verdict_evaluators import (
    LiveProbeEvidence,
    _indicator_verdict,  # type: ignore[attr-defined]
    _normalize_body,  # type: ignore[attr-defined]
    _timing_evaluate,  # type: ignore[attr-defined]
    _token_jaccard,  # type: ignore[attr-defined]
)

_NOW = datetime(2026, 6, 11, tzinfo=UTC)
REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def isolated_registry() -> Generator[None, None, None]:
    """Reset the registry so test registrations never leak across tests.

    Teardown restores the shipped builtins: leaving the registry empty leaks
    into later test files under xdist ``--dist loadfile`` (one worker runs
    many files in one process) and starves per-class routing there.
    """
    from quarry_activities import verdict_evaluators as ve

    ve.clear_evaluators()
    yield
    ve.clear_evaluators()
    ve.register_builtin_evaluators()


# Referenced so pyright's reportUnusedFunction does not fire on the fixture
# (pytest discovers fixtures by decorator; the reference below is the no-ignore
# equivalent of conftest.py's `# pyright: ignore[reportUnusedFunction]`).
_FIXTURES = (isolated_registry,)


def _make_finding(
    vuln_class: VulnerabilityClass = VulnerabilityClass.IDOR,
) -> CandidateFinding:
    return CandidateFinding(
        id="cf-ve-1",
        scan_id="scan-ve-test",
        workspace_id="ws-1",
        vuln_class=vuln_class,
        title="IDOR on /users/{id}",
        hypothesis="Unauthenticated user can read another user's profile.",
        affected_component="src/routes/users.py:42",
        root_cause_key="idor-users-id",
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
    )


def _make_capture(status_code: int = 200) -> HttpResponseCapture:
    return HttpResponseCapture(
        status_code=status_code,
        headers={"content-type": "application/json"},
        body_artifact_ref="art-resp-001",
        elapsed_ms=42,
        scrubber_hits=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        request_artifact_ref="art-req-001",
    )


# ---------------------------------------------------------------------------
# LiveProbeEvidence shape
# ---------------------------------------------------------------------------


class TestLiveProbeEvidence:
    def test_constructible_from_status_alone(self) -> None:
        from quarry_activities.verdict_evaluators import LiveProbeEvidence

        ev = LiveProbeEvidence(status_code=200)
        assert ev.status_code == 200
        assert ev.body_text is None
        assert ev.additional == ()

    def test_carries_resolved_body_and_differential_probes(self) -> None:
        from quarry_activities.verdict_evaluators import LiveProbeEvidence

        baseline = LiveProbeEvidence(status_code=200, body_text="[]")
        ev = LiveProbeEvidence(
            status_code=200,
            body_text='[{"id": 2}]',
            additional=(baseline,),
        )
        assert ev.body_text == '[{"id": 2}]'
        assert ev.additional == (baseline,)
        assert ev.additional[0].body_text == "[]"

    def test_frozen(self) -> None:
        from quarry_activities.verdict_evaluators import LiveProbeEvidence

        ev = LiveProbeEvidence(status_code=200)
        with pytest.raises(Exception, match="immutable|cannot assign|frozen"):
            ev.status_code = 500  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Registry: register / resolve / default fallback
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_register_and_resolve_per_class(self) -> None:
        from quarry_activities.verdict_evaluators import (
            register_evaluator,
            resolve_evaluator,
        )
        from quarry_workflows.run_scan import LIVE_NOT_CORROBORATED

        def fake(ev: LiveProbeEvidence) -> str:
            return LIVE_NOT_CORROBORATED

        register_evaluator(VulnerabilityClass.SSTI, fake)
        assert resolve_evaluator(VulnerabilityClass.SSTI) is fake

    def test_register_replaces_previous_registration(self) -> None:
        from quarry_activities.verdict_evaluators import (
            register_evaluator,
            resolve_evaluator,
        )

        def first(ev: object) -> str:
            return "corroborated"

        def second(ev: object) -> str:
            return "inconclusive"

        register_evaluator(VulnerabilityClass.SSTI, first)
        register_evaluator(VulnerabilityClass.SSTI, second)
        assert resolve_evaluator(VulnerabilityClass.SSTI) is second

    @pytest.mark.parametrize(
        ("status_code", "expected"),
        [
            (200, "corroborated"),
            (204, "corroborated"),
            (299, "corroborated"),
            (401, "not_corroborated"),
            (403, "not_corroborated"),
            (404, "not_corroborated"),
            (500, "inconclusive"),
            (302, "inconclusive"),
        ],
    )
    def test_unregistered_class_falls_back_to_default_status_evaluator(
        self, status_code: int, expected: str
    ) -> None:
        from quarry_activities.verdict_evaluators import (
            LiveProbeEvidence,
            evaluate_live_verdict,
            resolve_evaluator,
        )

        # Body/additional evidence must NOT change the default status-only verdict.
        ev = LiveProbeEvidence(
            status_code=status_code,
            body_text="anything",
            additional=(LiveProbeEvidence(status_code=200, body_text="base"),),
        )
        default = resolve_evaluator(VulnerabilityClass.LDAP_INJECTION)
        assert default(ev) == expected
        assert evaluate_live_verdict(VulnerabilityClass.LDAP_INJECTION, ev) == expected

    def test_evaluate_live_verdict_dispatches_to_registered_evaluator(self) -> None:
        from quarry_activities.verdict_evaluators import (
            LiveProbeEvidence,
            evaluate_live_verdict,
            register_evaluator,
        )
        from quarry_workflows.run_scan import LIVE_NOT_CORROBORATED

        seen: list[LiveProbeEvidence] = []

        def sentinel(ev: LiveProbeEvidence) -> str:
            seen.append(ev)
            return LIVE_NOT_CORROBORATED

        register_evaluator(VulnerabilityClass.SSTI, sentinel)
        ev = LiveProbeEvidence(status_code=200, body_text="49")
        assert evaluate_live_verdict(VulnerabilityClass.SSTI, ev) == LIVE_NOT_CORROBORATED
        assert seen == [ev]

    def test_verdict_source_per_class_and_default(self) -> None:
        from quarry_activities.verdict_evaluators import (
            LiveProbeEvidence,
            evaluate_live_verdict_with_source,
            register_evaluator,
        )
        from quarry_workflows.run_scan import LIVE_CORROBORATED, LIVE_INCONCLUSIVE

        def sentinel(ev: LiveProbeEvidence) -> str:
            return LIVE_INCONCLUSIVE

        register_evaluator(VulnerabilityClass.XXE, sentinel)
        verdict, source = evaluate_live_verdict_with_source(
            VulnerabilityClass.XXE, LiveProbeEvidence(status_code=200)
        )
        assert (verdict, source) == (LIVE_INCONCLUSIVE, "per_class")

        verdict, source = evaluate_live_verdict_with_source(
            VulnerabilityClass.WEAK_CRYPTO, LiveProbeEvidence(status_code=200)
        )
        assert (verdict, source) == (LIVE_CORROBORATED, "default")


# ---------------------------------------------------------------------------
# Vocabulary single-sourcing (run_scan re-exports the canonical definitions)
# ---------------------------------------------------------------------------


class TestVocabularySingleSourcing:
    def test_run_scan_reexports_canonical_vocabulary(self) -> None:
        import importlib

        from quarry_activities.verdict_evaluators import (
            LIVE_CORROBORATED,
            LIVE_INCONCLUSIVE,
            LIVE_NOT_CORROBORATED,
            live_verdict_from_status,
        )

        # quarry_workflows.__init__ re-exports the run_scan FUNCTION (shadowing
        # the submodule name), so fetch the module itself.
        run_scan = importlib.import_module("quarry_workflows.run_scan")

        assert run_scan.LIVE_CORROBORATED == LIVE_CORROBORATED == "corroborated"
        assert run_scan.LIVE_NOT_CORROBORATED == LIVE_NOT_CORROBORATED == ("not_corroborated")
        assert run_scan.LIVE_INCONCLUSIVE == LIVE_INCONCLUSIVE == "inconclusive"
        # Same function object — no duplicated logic.
        assert run_scan.live_verdict_from_status is live_verdict_from_status


# ---------------------------------------------------------------------------
# resolve_live_verdict: evidence routing (dynamic_validate_stage wiring)
# ---------------------------------------------------------------------------


class TestResolveLiveVerdictEvidenceRouting:
    def test_registered_evaluator_consulted_when_evidence_provided(self) -> None:
        from quarry_activities.verdict_evaluators import (
            LiveProbeEvidence,
            register_evaluator,
        )
        from quarry_workflows.dynamic_validate_stage import resolve_live_verdict
        from quarry_workflows.run_scan import LIVE_NOT_CORROBORATED

        seen: list[LiveProbeEvidence] = []

        def sentinel(ev: LiveProbeEvidence) -> str:
            seen.append(ev)
            return LIVE_NOT_CORROBORATED

        register_evaluator(VulnerabilityClass.IDOR, sentinel)
        ev = LiveProbeEvidence(status_code=200, body_text="hello")
        verdict, link = resolve_live_verdict(
            candidate=_make_finding(VulnerabilityClass.IDOR),
            capture=_make_capture(status_code=200),
            scan_id="scan-ve-test",
            now=_NOW,
            evidence=ev,
        )
        # A 2xx capture would corroborate under status-only rules; the per-class
        # evaluator's verdict wins instead.
        assert verdict == LIVE_NOT_CORROBORATED
        assert link is None
        assert seen == [ev]

    def test_registry_corroboration_promotes_with_evidence_link(self) -> None:
        from quarry.schemas import DynamicEvidenceLink
        from quarry_activities.verdict_evaluators import (
            LiveProbeEvidence,
            register_evaluator,
        )
        from quarry_workflows.dynamic_validate_stage import resolve_live_verdict
        from quarry_workflows.run_scan import LIVE_CORROBORATED

        def corroborator(ev: LiveProbeEvidence) -> str:
            return LIVE_CORROBORATED

        register_evaluator(VulnerabilityClass.IDOR, corroborator)
        verdict, link = resolve_live_verdict(
            candidate=_make_finding(VulnerabilityClass.IDOR),
            capture=_make_capture(status_code=200),
            scan_id="scan-ve-test",
            now=_NOW,
            evidence=LiveProbeEvidence(status_code=200, body_text="ok"),
        )
        assert verdict == LIVE_CORROBORATED
        assert isinstance(link, DynamicEvidenceLink)

    def test_status_only_when_evidence_absent(self) -> None:
        """evidence=None keeps the current behavior; registry is NOT consulted."""
        from quarry_activities.verdict_evaluators import (
            register_evaluator,
        )
        from quarry_workflows.dynamic_validate_stage import resolve_live_verdict
        from quarry_workflows.run_scan import LIVE_CORROBORATED, LIVE_NOT_CORROBORATED

        def sentinel(ev: LiveProbeEvidence) -> str:
            return LIVE_NOT_CORROBORATED

        register_evaluator(VulnerabilityClass.IDOR, sentinel)
        verdict, link = resolve_live_verdict(
            candidate=_make_finding(VulnerabilityClass.IDOR),
            capture=_make_capture(status_code=200),
            scan_id="scan-ve-test",
            now=_NOW,
        )
        assert verdict == LIVE_CORROBORATED  # status-only path: 2xx corroborates
        assert link is not None

    def test_default_evaluator_used_when_evidence_provided_but_class_unregistered(
        self,
    ) -> None:
        from quarry_activities.verdict_evaluators import LiveProbeEvidence
        from quarry_workflows.dynamic_validate_stage import resolve_live_verdict
        from quarry_workflows.run_scan import LIVE_NOT_CORROBORATED

        verdict, link = resolve_live_verdict(
            candidate=_make_finding(VulnerabilityClass.LDAP_INJECTION),
            capture=_make_capture(status_code=403),
            scan_id="scan-ve-test",
            now=_NOW,
            evidence=LiveProbeEvidence(status_code=403, body_text="Forbidden"),
        )
        assert verdict == LIVE_NOT_CORROBORATED
        assert link is None


# ---------------------------------------------------------------------------
# run_scan wiring (source-level; the workflow runs under Temporal)
# ---------------------------------------------------------------------------


class TestRunScanWiring:
    def test_dynamic_validate_block_evaluates_via_registry(self) -> None:
        source = (REPO_ROOT / "src" / "quarry_workflows" / "run_scan.py").read_text(
            encoding="utf-8"
        )
        assert "live_verdict_from_status(capture.status_code)" not in source, (
            "the hardcoded status-only verdict call must be replaced by the "
            "per-class registry evaluation"
        )
        assert "evaluate_live_verdict_with_source" in source
        assert '"verdict_source"' in source

    def test_dynamic_validate_block_resolves_body_via_activity(self) -> None:
        source = (REPO_ROOT / "src" / "quarry_workflows" / "run_scan.py").read_text(
            encoding="utf-8"
        )
        assert '"read-artifact-text"' in source, (
            "body artifacts must be resolved to text activity-side (workflow code stays I/O-free)"
        )

    def test_capture_carries_body_artifact_key(self) -> None:
        """body_artifact_ref is a uuid id; the store is key-addressed.

        Per-class body evaluators need the capture to carry the store KEY the
        response artifact was written under, else bodies are unresolvable.
        """
        from quarry.schemas import HttpResponseCapture, RedactionStatus

        cap = HttpResponseCapture(
            status_code=200,
            headers={},
            body_artifact_ref="art-resp-001",
            elapsed_ms=42,
            redaction_status=RedactionStatus.NOT_REQUIRED,
            body_artifact_key="http/responses/200_x_abc.json",
        )
        assert cap.body_artifact_key == "http/responses/200_x_abc.json"
        # Optional — legacy captures (and test fixtures) construct without it.
        legacy = HttpResponseCapture(
            status_code=200,
            headers={},
            body_artifact_ref="art-resp-001",
            elapsed_ms=42,
            redaction_status=RedactionStatus.NOT_REQUIRED,
        )
        assert legacy.body_artifact_key is None


# ---------------------------------------------------------------------------
# Differential hardening helpers — payload-echo normalization (task 2),
# token-Jaccard similarity (task 3), indicator override (task 4).
# ---------------------------------------------------------------------------


class TestNormalizeBody:
    def test_normalize_body_replaces_injected_value(self) -> None:
        assert _normalize_body("a=1' OR '1'='1", ("1' OR '1'='1",)) == "a=§INJECTED§"

    def test_normalize_body_replaces_every_injected_value(self) -> None:
        assert _normalize_body("x=foo&y=bar", ("foo", "bar")) == "x=§INJECTED§&y=§INJECTED§"

    def test_normalize_body_without_values_is_identity(self) -> None:
        assert _normalize_body("unchanged body", ()) == "unchanged body"

    def test_normalize_body_skips_empty_values(self) -> None:
        # ``str.replace("")`` would insert the placeholder between every char.
        assert _normalize_body("abc", ("",)) == "abc"


class TestTokenJaccard:
    def test_token_jaccard_identical_bodies(self) -> None:
        assert _token_jaccard("alpha beta gamma", "alpha beta gamma") == 1.0

    def test_token_jaccard_both_empty_bodies(self) -> None:
        assert _token_jaccard("", "") == 1.0

    def test_token_jaccard_one_empty_one_non_empty(self) -> None:
        assert _token_jaccard("", "rows") == 0.0

    def test_token_jaccard_disjoint_bodies(self) -> None:
        assert _token_jaccard("alpha beta", "gamma delta") == 0.0

    def test_token_jaccard_partial_overlap(self) -> None:
        # {a,b} ∩ {b,c} = {b} (1); ∪ = {a,b,c} (3) → 1/3.
        assert _token_jaccard("a b", "b c") == pytest.approx(1 / 3)


class TestIndicatorVerdict:
    def test_indicator_verdict_present_in_attack_only_corroborates(self) -> None:
        assert _indicator_verdict("uid=0(root)", "denied", "uid=0(root)") == "corroborated"

    def test_indicator_verdict_absent_from_both_not_corroborated(self) -> None:
        assert _indicator_verdict("denied", "denied", "uid=0(root)") == "not_corroborated"

    def test_indicator_verdict_present_in_both_falls_through(self) -> None:
        assert _indicator_verdict("marker", "marker", "marker") is None

    def test_indicator_verdict_none_is_noop(self) -> None:
        assert _indicator_verdict("uid=0(root)", "denied", None) is None


# ---------------------------------------------------------------------------
# Hardened differential path (SQLi non-delay + SSRF) — indicator → normalization
# → token-Jaccard → exact comparison.
# ---------------------------------------------------------------------------


class TestHardenedDifferentialPath:
    def test_payload_echo_normalized_away_is_not_corroborated(self) -> None:
        """R4 S1: distinct injected values, otherwise identical structure."""
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="result for 1' OR '1'='1",
            additional=(LiveProbeEvidence(status_code=200, body_text="result for 999999"),),
            injected_values=("1' OR '1'='1", "999999"),
        )
        assert sql_injection_evaluator(ev) == "not_corroborated"

    def test_echo_only_difference_without_declared_values_corroborates(self) -> None:
        """No declared injected values → normalization is a no-op, bodies diverge.

        Pins the reason ``injected_values`` must be agent-declared rather than
        guessed: without it the reflected-payload false positive survives.
        """
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="result for 1' OR '1'='1",
            additional=(LiveProbeEvidence(status_code=200, body_text="result for 999999"),),
        )
        assert sql_injection_evaluator(ev) == "corroborated"

    def test_jaccard_equivalence_matching_status_not_corroborated(self) -> None:
        """R5 S1: ≥ 0.95 similarity with matching status → equivalent."""
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        body = "alpha beta gamma delta"
        ev = LiveProbeEvidence(
            status_code=200,
            body_text=body,
            additional=(LiveProbeEvidence(status_code=200, body_text=body),),
        )
        assert sql_injection_evaluator(ev) == "not_corroborated"

    def test_jaccard_equivalence_mismatched_status_inconclusive(self) -> None:
        """R5 S2: equivalent bodies but the server treated them differently."""
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        body = "alpha beta gamma delta"
        ev = LiveProbeEvidence(
            status_code=200,
            body_text=body,
            additional=(LiveProbeEvidence(status_code=403, body_text=body),),
        )
        assert sql_injection_evaluator(ev) == "inconclusive"

    def test_high_similarity_mismatched_status_inconclusive(self) -> None:
        """Near-but-not-identical bodies still clear the 0.95 similarity gate."""
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        shared = " ".join(f"tok{i}" for i in range(40))
        ev = LiveProbeEvidence(
            status_code=200,
            body_text=f"{shared} extra",
            additional=(LiveProbeEvidence(status_code=500, body_text=f"{shared} other"),),
        )
        # 40 shared tokens, one distinct each side → 40/42 ≈ 0.952 ≥ 0.95.
        assert _token_jaccard(f"{shared} extra", f"{shared} other") >= 0.95
        assert sql_injection_evaluator(ev) == "inconclusive"

    def test_high_similarity_matching_status_not_corroborated(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        shared = " ".join(f"tok{i}" for i in range(40))
        ev = LiveProbeEvidence(
            status_code=200,
            body_text=f"{shared} extra",
            additional=(LiveProbeEvidence(status_code=200, body_text=f"{shared} other"),),
        )
        assert sql_injection_evaluator(ev) == "not_corroborated"

    def test_below_similarity_divergence_falls_through_to_exact_comparison(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="alpha beta gamma",
            additional=(LiveProbeEvidence(status_code=200, body_text="zzz"),),
        )
        assert sql_injection_evaluator(ev) == "corroborated"

    def test_indicator_override_present_in_attack_only(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="uid=0(root)",
            additional=(LiveProbeEvidence(status_code=200, body_text="[]"),),
            indicator="uid=0(root)",
        )
        assert sql_injection_evaluator(ev) == "corroborated"

    def test_indicator_absent_from_both_short_circuits(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="[]",
            additional=(LiveProbeEvidence(status_code=200, body_text="other"),),
            indicator="uid=0(root)",
        )
        assert sql_injection_evaluator(ev) == "not_corroborated"

    def test_indicator_present_in_both_falls_through(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        body = "marker present in both"
        ev = LiveProbeEvidence(
            status_code=200,
            body_text=body,
            additional=(LiveProbeEvidence(status_code=200, body_text=body),),
            indicator="marker",
        )
        assert sql_injection_evaluator(ev) == "not_corroborated"

    def test_ssrf_shares_the_hardened_path(self) -> None:
        from quarry_activities.verdict_evaluators import ssrf_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="nested-fetch-ok",
            additional=(LiveProbeEvidence(status_code=400, body_text="rejected"),),
            indicator="nested-fetch-ok",
        )
        assert ssrf_evaluator(ev) == "corroborated"

    def test_non_2xx_primary_inconclusive_regardless_of_divergence(self) -> None:
        from quarry_activities.verdict_evaluators import sql_injection_evaluator

        ev = LiveProbeEvidence(
            status_code=500,
            body_text="boom",
            additional=(LiveProbeEvidence(status_code=200, body_text="[]"),),
        )
        assert sql_injection_evaluator(ev) == "inconclusive"


# ---------------------------------------------------------------------------
# Statistical timing path (tasks 6/7/11)
# ---------------------------------------------------------------------------

_STEADY_BASELINE = (100, 100, 100, 100, 100)
_NOISY_BASELINE = (100, 110, 120, 130, 140)


def _timing_probe(elapsed_ms: int, *, status_code: int = 200) -> LiveProbeEvidence:
    return LiveProbeEvidence(status_code=status_code, body_text="ok", elapsed_ms=elapsed_ms)


def _timing_batch(
    *,
    baseline: Sequence[int],
    attacks: Sequence[int],
    ladder: Sequence[int] = (),
    injected_delay_ms: int | None = 1000,
) -> LiveProbeEvidence:
    """Build the single timing-evidence batch the workflow assembles.

    primary = first attack probe; additional = N baseline probes, then the
    remaining M-1 attack probes, then (once the ladder ran) the M ladder probes.
    """
    attack_probes = [_timing_probe(v) for v in attacks]
    primary = attack_probes[0]
    additional = (
        tuple(_timing_probe(v) for v in baseline)
        + tuple(attack_probes[1:])
        + tuple(_timing_probe(v) for v in ladder)
    )
    return LiveProbeEvidence(
        status_code=primary.status_code,
        body_text=primary.body_text,
        additional=additional,
        elapsed_ms=primary.elapsed_ms,
        injected_delay_ms=injected_delay_ms,
    )


class TestTimingPath:
    def test_timing_path_clear_delay_is_statistical_pass(self) -> None:
        verdict, receipt = _timing_evaluate(
            _timing_batch(baseline=_STEADY_BASELINE, attacks=(700, 700, 700)), 1000
        )
        assert verdict == "statistical_pass"
        assert receipt.reason == "statistical_pass"
        assert receipt.induced_delay_ms == 600.0
        assert receipt.majority_count == 3
        assert receipt.majority_required == 2
        assert receipt.ladder_scale_factor is None  # ladder not run yet

    def test_timing_path_negligible_delay_not_corroborated(self) -> None:
        verdict, receipt = _timing_evaluate(
            _timing_batch(baseline=_NOISY_BASELINE, attacks=(120, 120, 120)), 1000
        )
        assert verdict == "not_corroborated"
        assert receipt.reason == "below_noise_floor"

    def test_timing_path_below_combined_threshold_inconclusive(self) -> None:
        # Induced delay clears 3σ but not the 0.6 × injected-delay floor.
        verdict, receipt = _timing_evaluate(
            _timing_batch(baseline=_NOISY_BASELINE, attacks=(650, 650, 100)), 1000
        )
        assert verdict == "inconclusive"
        assert receipt.reason == "inconclusive"
        assert receipt.majority_count == 2  # majority met; the threshold failed

    def test_timing_path_zero_baseline_variance_uses_delay_fraction(self) -> None:
        verdict, receipt = _timing_evaluate(
            _timing_batch(baseline=_STEADY_BASELINE, attacks=(700, 700, 700)), 1000
        )
        assert receipt.classical_sigma == 0.0
        assert receipt.robust_sigma == 0.0
        # zero variance → the noise floor is the 0.6 × injected_delay term
        assert receipt.threshold == 600.0
        assert verdict == "statistical_pass"

    def test_timing_path_inclusive_boundary_is_pass(self) -> None:
        # Source uses inclusive comparators: induced == threshold still passes.
        verdict, receipt = _timing_evaluate(
            _timing_batch(baseline=_STEADY_BASELINE, attacks=(700, 700, 700)), 1000
        )
        assert receipt.induced_delay_ms == receipt.threshold == 600.0
        assert verdict == "statistical_pass"

    def test_timing_path_insufficient_samples_inconclusive(self) -> None:
        partial = LiveProbeEvidence(
            status_code=200,
            body_text="ok",
            elapsed_ms=700,
            injected_delay_ms=1000,
            additional=(LiveProbeEvidence(status_code=200, body_text="ok", elapsed_ms=100),),
        )
        verdict, receipt = _timing_evaluate(partial, 1000)
        assert verdict == "inconclusive"
        assert receipt.reason == "insufficient_timing_samples"

    def test_timing_path_usable_without_declared_injected_values(self) -> None:
        # Timing samples need no body/injected-values annotation.
        verdict, _receipt = _timing_evaluate(
            _timing_batch(baseline=_STEADY_BASELINE, attacks=(700, 700, 700)), 1000
        )
        assert verdict == "statistical_pass"


class TestTimingLadder:
    def test_timing_ladder_scaling_confirms(self) -> None:
        verdict, receipt = _timing_evaluate(
            _timing_batch(
                baseline=_STEADY_BASELINE,
                attacks=(700, 700, 700),
                ladder=(1300, 1300, 1300),
            ),
            1000,
        )
        assert verdict == "corroborated"
        assert receipt.reason == "ladder_confirmed"
        assert receipt.ladder_scale_factor == pytest.approx(2.0)

    def test_timing_ladder_insufficient_scaling_inconclusive(self) -> None:
        verdict, receipt = _timing_evaluate(
            _timing_batch(
                baseline=_STEADY_BASELINE,
                attacks=(700, 700, 700),
                ladder=(766, 766, 766),
            ),
            1000,
        )
        assert verdict == "inconclusive"
        assert receipt.reason == "ladder_failed_to_scale"
        assert receipt.ladder_scale_factor == pytest.approx(1.11, abs=0.01)

    def test_timing_ladder_scale_ok_but_additive_floor_fails(self) -> None:
        verdict, receipt = _timing_evaluate(
            _timing_batch(
                baseline=_STEADY_BASELINE,
                attacks=(700, 700, 700),
                ladder=(1000, 1000, 1000),
            ),
            1000,
        )
        assert receipt.ladder_scale_factor == pytest.approx(1.5)
        assert verdict == "inconclusive"
        assert receipt.reason == "ladder_failed_to_scale"

    def test_timing_ladder_ignored_without_statistical_pass(self) -> None:
        verdict, receipt = _timing_evaluate(
            _timing_batch(
                baseline=_NOISY_BASELINE,
                attacks=(120, 120, 120),
                ladder=(240, 240, 240),
            ),
            1000,
        )
        assert verdict == "not_corroborated"
        assert receipt.ladder_scale_factor is None


class TestTimingReceipt:
    def test_timing_receipt_corroborated_carries_full_stats(self) -> None:
        from quarry_activities.verdict_evaluators import (
            evaluate_live_verdict_with_receipt,
            register_builtin_evaluators,
        )

        register_builtin_evaluators()
        evidence = _timing_batch(
            baseline=_STEADY_BASELINE,
            attacks=(700, 700, 700),
            ladder=(1300, 1300, 1300),
        )
        verdict, receipt = evaluate_live_verdict_with_receipt(
            VulnerabilityClass.SQL_INJECTION, evidence
        )
        assert verdict == "corroborated"
        assert receipt is not None
        assert (receipt.n, receipt.m) == (5, 3)
        assert receipt.baseline_median == 100.0
        assert receipt.attack_median == 700.0
        assert receipt.threshold == 600.0
        assert receipt.ladder_scale_factor == pytest.approx(2.0)

    def test_timing_receipt_absent_for_non_timing_evidence(self) -> None:
        from quarry_activities.verdict_evaluators import (
            evaluate_live_verdict_with_receipt,
            register_builtin_evaluators,
        )

        register_builtin_evaluators()
        evidence = LiveProbeEvidence(
            status_code=200,
            body_text="a",
            additional=(LiveProbeEvidence(status_code=200, body_text="b"),),
        )
        verdict, receipt = evaluate_live_verdict_with_receipt(
            VulnerabilityClass.SQL_INJECTION, evidence
        )
        assert receipt is None
        assert verdict == "corroborated"

    def test_timing_receipt_serializes_with_every_reported_field(self) -> None:
        import json
        from dataclasses import asdict

        _, receipt = _timing_evaluate(
            _timing_batch(
                baseline=_STEADY_BASELINE,
                attacks=(700, 700, 700),
                ladder=(1300, 1300, 1300),
            ),
            1000,
        )
        payload = asdict(receipt)
        assert set(payload) == {
            "n",
            "m",
            "baseline_median",
            "attack_median",
            "mad",
            "robust_sigma",
            "classical_sigma",
            "threshold",
            "induced_delay_ms",
            "majority_count",
            "majority_required",
            "ladder_scale_factor",
            "reason",
        }
        # The workflow serializes the receipt as a JSON string onto the event.
        assert json.loads(json.dumps(payload))["n"] == 5
