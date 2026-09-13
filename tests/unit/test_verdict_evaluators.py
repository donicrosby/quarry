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

from collections.abc import Generator
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
            LiveProbeEvidence,
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
            LiveProbeEvidence,
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
