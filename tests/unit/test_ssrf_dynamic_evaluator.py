"""SSRF per-class dynamic evaluator + target-origin-aware fallback pair.

Written RED first — fails until ``ssrf_evaluator`` exists in
``src/quarry_activities/verdict_evaluators.py`` and the target-origin-aware
SSRF pair builder exists in ``src/quarry_workflows/run_scan.py``.

Locked contracts:

- ``ssrf_evaluator`` (registered under ``SSRF`` with ``min_probes=2``): no
  baseline → inconclusive (the differential needs the pair); primary non-2xx →
  inconclusive; either body unresolvable → inconclusive; identical bodies →
  not_corroborated; 2xx primary + diverging bodies → corroborated (the pair is
  constructed so divergence means the userinfo bypass fetched nested-endpoint
  content the baseline's disallowed URL cannot reach).
- Registration: SSRF routes per-class on module import and needs a probe PAIR
  — ``differential_baseline_permitted`` admits the baseline probe.
- Fallback pair builder: the nested (inner) URL derives scheme/host/port from
  the scan target's ``TargetEndpoint`` (never a hardcoded localhost port); the
  bypass payload URL-encodes the userinfo trick; the baseline uses a reserved,
  never-resolving authority.  Builders CONSTRUCT specs only — no HTTP.
- The broken static SSRF single-probe entry is gone: SSRF has no single-probe
  fallback; other classes keep theirs untouched.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime

import pytest

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    FindingStatus,
    HttpRequestSpec,
    Severity,
    SourceRef,
    TargetEndpoint,
    VulnerabilityClass,
)
from quarry_activities.verdict_evaluators import LiveProbeEvidence
from quarry_workflows.run_scan import (
    build_dynamic_probe_spec,
    build_dynamic_probe_spec_pair,
    build_target_endpoint_from_url,
    differential_baseline_permitted,
    select_dynamic_probe_specs,
)

_NOW = datetime(2026, 6, 13, tzinfo=UTC)
_SCAN_ID = "scan-ssrf-eval"

# The motivating target: examples/vulnerable-fastapi on its dev port.
_TARGET_URL = "http://127.0.0.1:8001"


@pytest.fixture(autouse=True)
def builtin_evaluators_registered() -> Generator[None, None, None]:
    """Ensure the builtin evaluators are registered regardless of test order."""
    from quarry_activities.verdict_evaluators import register_builtin_evaluators

    register_builtin_evaluators()
    yield
    register_builtin_evaluators()


# Referenced so pyright's reportUnusedFunction does not fire on the fixture.
_FIXTURES = (builtin_evaluators_registered,)


def _ssrf_candidate() -> CandidateFinding:
    return CandidateFinding(
        id="cf-ssrf-eval-1",
        scan_id=_SCAN_ID,
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.SSRF,
        title="SSRF in /fetch-local",
        hypothesis="The url parameter is prefix-validated then fetched server-side.",
        affected_component="app.py:112",
        root_cause_key="ssrf-fetch-local-url",
        hunter_provider="mock",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
        source_refs=[
            SourceRef(
                file_path="app.py",
                start_line=112,
                end_line=118,
                symbol="fetch_local",
            )
        ],
        status=FindingStatus.NEEDS_PROOF,
    )


# ---------------------------------------------------------------------------
# ssrf_evaluator — every branch
# ---------------------------------------------------------------------------


class TestSsrfEvaluator:
    def test_bypass_pair_with_nested_content_corroborates(self) -> None:
        """Primary fetched the nested endpoint; baseline was rejected."""
        from quarry_activities.verdict_evaluators import ssrf_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text=(
                '{"requested_url": "http://localhost@127.0.0.1:8001/users/1", '
                '"status": "200", "body": "{\\"id\\": \\"1\\", \\"name\\": \\"Ada\\"}"}'
            ),
            additional=(
                LiveProbeEvidence(
                    status_code=400,
                    body_text='{"detail": "Only local URLs are accepted"}',
                ),
            ),
        )
        assert ssrf_evaluator(ev) == "corroborated"

    def test_identical_bodies_not_corroborated(self) -> None:
        """The parameter drives no observable difference → no SSRF signal."""
        from quarry_activities.verdict_evaluators import ssrf_evaluator

        same = '{"detail": "Only local URLs are accepted"}'
        ev = LiveProbeEvidence(
            status_code=200,
            body_text=same,
            additional=(LiveProbeEvidence(status_code=400, body_text=same),),
        )
        assert ssrf_evaluator(ev) == "not_corroborated"

    def test_single_probe_inconclusive(self) -> None:
        """No baseline → the differential cannot decide, even on a 2xx body."""
        from quarry_activities.verdict_evaluators import ssrf_evaluator

        ev = LiveProbeEvidence(status_code=200, body_text="fetched")
        assert ssrf_evaluator(ev) == "inconclusive"

    @pytest.mark.parametrize("status_code", [500, 404, 403, 400, 302])
    def test_primary_non_2xx_inconclusive(self, status_code: int) -> None:
        """Guard rejected the bypass OR the nested fetch errored (incl. the
        app's own 500 when the nested origin is unreachable) → cannot decide."""
        from quarry_activities.verdict_evaluators import ssrf_evaluator

        ev = LiveProbeEvidence(
            status_code=status_code,
            body_text="Internal Server Error",
            additional=(
                LiveProbeEvidence(
                    status_code=400,
                    body_text='{"detail": "Only local URLs are accepted"}',
                ),
            ),
        )
        assert ssrf_evaluator(ev) == "inconclusive"

    @pytest.mark.parametrize(
        ("primary_body", "baseline_body"),
        [
            (None, '{"detail": "Only local URLs are accepted"}'),
            ("fetched", None),
            (None, None),
        ],
    )
    def test_unresolvable_body_inconclusive(
        self, primary_body: str | None, baseline_body: str | None
    ) -> None:
        from quarry_activities.verdict_evaluators import ssrf_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text=primary_body,
            additional=(LiveProbeEvidence(status_code=400, body_text=baseline_body),),
        )
        assert ssrf_evaluator(ev) == "inconclusive"

    def test_baseline_status_not_consulted(self) -> None:
        """Only the primary's status gates the verdict; the diff is textual."""
        from quarry_activities.verdict_evaluators import ssrf_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="nested content",
            additional=(LiveProbeEvidence(status_code=200, body_text="other"),),
        )
        assert ssrf_evaluator(ev) == "corroborated"

    def test_extra_probes_beyond_baseline_ignored(self) -> None:
        from quarry_activities.verdict_evaluators import ssrf_evaluator

        same = '{"detail": "Only local URLs are accepted"}'
        ev = LiveProbeEvidence(
            status_code=200,
            body_text=same,
            additional=(
                LiveProbeEvidence(status_code=400, body_text=same),
                LiveProbeEvidence(status_code=200, body_text="zzz"),
            ),
        )
        assert ssrf_evaluator(ev) == "not_corroborated"


# ---------------------------------------------------------------------------
# Registration hygiene: SSRF routes per-class after import, needs a PAIR
# ---------------------------------------------------------------------------


class TestSsrfRegistration:
    def test_module_import_registers_ssrf_evaluator(self) -> None:
        """A FRESH interpreter import registers SSRF (no reload — see the
        SSTI/SQLi file for why reloading is avoided).  The subprocess pins
        PYTHONPATH to THIS repo's src/ so it tests this checkout even when a
        sibling editable install of quarry sits in site-packages."""
        import os
        import subprocess
        import sys
        from pathlib import Path

        repo_src = str(Path(__file__).resolve().parents[2] / "src")
        code = (
            "from quarry.schemas import VulnerabilityClass\n"
            "import quarry_activities.verdict_evaluators as ve\n"
            "assert ve.resolve_evaluator(VulnerabilityClass.SSRF) is ve.ssrf_evaluator\n"
            "assert ve.resolve_evaluator_spec(VulnerabilityClass.SSRF).min_probes == 2\n"
            "print('ok')\n"
        )
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "PYTHONPATH": repo_src},
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "ok"

    def test_ssrf_resolves_with_min_probes_two(self) -> None:
        from quarry_activities.verdict_evaluators import (
            resolve_evaluator,
            resolve_evaluator_spec,
            ssrf_evaluator,
        )

        assert resolve_evaluator(VulnerabilityClass.SSRF) is ssrf_evaluator
        assert resolve_evaluator_spec(VulnerabilityClass.SSRF).min_probes == 2

    def test_ssrf_routes_per_class_with_source_tag(self) -> None:
        from quarry_activities.verdict_evaluators import evaluate_live_verdict_with_source

        ev = LiveProbeEvidence(
            status_code=200,
            body_text="nested content",
            additional=(LiveProbeEvidence(status_code=400, body_text="rejected"),),
        )
        assert evaluate_live_verdict_with_source(VulnerabilityClass.SSRF, ev) == (
            "corroborated",
            "per_class",
        )

    def test_ssrf_baseline_permitted_with_uncapped_budget(self) -> None:
        assert differential_baseline_permitted(VulnerabilityClass.SSRF, budget_remaining=None)

    def test_ssrf_baseline_refused_without_budget(self) -> None:
        assert not differential_baseline_permitted(VulnerabilityClass.SSRF, budget_remaining=0.0)


# ---------------------------------------------------------------------------
# Target-origin-aware fallback pair builder
# ---------------------------------------------------------------------------


class TestSsrfFallbackPairBuilder:
    def test_pair_paths_derive_from_target_endpoint(self) -> None:
        """Exact strings: userinfo-bypass nested URL on the target's own
        origin, fully URL-encoded as the ``url`` query param."""
        endpoint = build_target_endpoint_from_url(_TARGET_URL)
        pair = build_dynamic_probe_spec_pair(_ssrf_candidate(), endpoint)
        assert pair == (
            HttpRequestSpec(
                method="GET",
                path="/fetch-local?url=http%3A%2F%2Flocalhost%40127.0.0.1%3A8001%2Fusers%2F1",
            ),
            HttpRequestSpec(
                method="GET",
                path="/fetch-local?url=http%3A%2F%2Fssrf-baseline.invalid%2Fusers%2F1",
            ),
        )

    def test_pair_derives_custom_scheme_host_port_and_base_path(self) -> None:
        """Nothing is hardcoded to a localhost dev port — a remote https
        target with a base path yields its own origin inside the bypass."""
        endpoint = TargetEndpoint(
            host="api.example.test", port=8443, scheme="https", base_path="/v1"
        )
        pair = build_dynamic_probe_spec_pair(_ssrf_candidate(), endpoint)
        assert pair is not None
        primary, baseline = pair
        assert primary.path == (
            "/fetch-local?url=http%3A%2F%2Flocalhost%40api.example.test%3A8443%2Fv1%2Fusers%2F1"
        )
        assert baseline.path == (
            "/fetch-local?url=http%3A%2F%2Fssrf-baseline.invalid%2Fv1%2Fusers%2F1"
        )
        # The nested origin is the scan target, never a hardcoded host:port.
        assert "8001" not in primary.path
        assert "127.0.0.1" not in primary.path.split("localhost%40", 1)[1].split("%3A")[0]

    def test_pair_without_endpoint_returns_none(self) -> None:
        """No origin to derive from → no fallback (never a hardcoded guess)."""
        assert build_dynamic_probe_spec_pair(_ssrf_candidate()) is None

    def test_broken_single_probe_entry_removed(self) -> None:
        """SSRF no longer has a static single-probe fallback (the old entry
        targeted port 80 where nothing listens)."""
        assert build_dynamic_probe_spec(_ssrf_candidate()) is None

    def test_other_classes_single_probe_untouched(self) -> None:
        for vuln_class, expected_path in (
            (VulnerabilityClass.IDOR, "/users/1"),
            (VulnerabilityClass.COMMAND_INJECTION, "/debug/ping?host=127.0.0.1"),
            (VulnerabilityClass.XSS, "/"),
        ):
            candidate = _ssrf_candidate().model_copy(
                update={"vuln_class": vuln_class, "root_cause_key": f"{vuln_class.value}-x"}
            )
            spec = build_dynamic_probe_spec(candidate)
            assert spec is not None
            assert spec.path == expected_path

    def test_sqli_static_pair_untouched(self) -> None:
        candidate = _ssrf_candidate().model_copy(
            update={"vuln_class": VulnerabilityClass.SQL_INJECTION}
        )
        pair = build_dynamic_probe_spec_pair(candidate)
        assert pair is not None
        assert "OR%201%3D1" in pair[0].path
        assert "AND%201%3D2" in pair[1].path


# ---------------------------------------------------------------------------
# Dispatch through select_dynamic_probe_specs
# ---------------------------------------------------------------------------


class TestSelectDynamicProbeSpecsSsrf:
    def test_no_proposals_uses_target_aware_pair(self) -> None:
        endpoint = build_target_endpoint_from_url(_TARGET_URL)
        specs = select_dynamic_probe_specs([], _ssrf_candidate(), endpoint)
        assert len(specs) == 2
        assert specs[0].method == "GET" == specs[1].method
        assert specs[0].path == (
            "/fetch-local?url=http%3A%2F%2Flocalhost%40127.0.0.1%3A8001%2Fusers%2F1"
        )
        assert specs[1].path == ("/fetch-local?url=http%3A%2F%2Fssrf-baseline.invalid%2Fusers%2F1")
        for spec in specs:
            assert spec.auth_profile is None

    def test_no_proposals_without_endpoint_returns_empty(self) -> None:
        """Cannot derive the nested origin → no doomed hardcoded probe."""
        assert select_dynamic_probe_specs([], _ssrf_candidate()) == []

    def test_agent_pair_preferred_over_fallback(self) -> None:
        endpoint = build_target_endpoint_from_url(_TARGET_URL)
        specs = select_dynamic_probe_specs(
            [
                {
                    "method": "GET",
                    "path": "/fetch-local?url=http%3A%2F%2Flocalhost%40127.0.0.1%3A8001%2Fhealth",
                },
                {"method": "GET", "path": "/fetch-local?url=http%3A%2F%2Fexample.invalid%2F"},
            ],
            _ssrf_candidate(),
            endpoint,
        )
        assert [s.path for s in specs] == [
            "/fetch-local?url=http%3A%2F%2Flocalhost%40127.0.0.1%3A8001%2Fhealth",
            "/fetch-local?url=http%3A%2F%2Fexample.invalid%2F",
        ]

    def test_single_proposal_gets_built_baseline(self) -> None:
        endpoint = build_target_endpoint_from_url(_TARGET_URL)
        specs = select_dynamic_probe_specs(
            [
                {
                    "method": "GET",
                    "path": "/fetch-local?url=http%3A%2F%2Flocalhost%40127.0.0.1%3A8001%2Fhealth",
                }
            ],
            _ssrf_candidate(),
            endpoint,
        )
        assert [s.path for s in specs] == [
            "/fetch-local?url=http%3A%2F%2Flocalhost%40127.0.0.1%3A8001%2Fhealth",
            "/fetch-local?url=http%3A%2F%2Fssrf-baseline.invalid%2Fusers%2F1",
        ]

    def test_single_proposal_without_endpoint_dispatches_one(self) -> None:
        """No origin → only the agent's proposal dispatches (evaluator will
        read the missing baseline as inconclusive, never error)."""
        specs = select_dynamic_probe_specs(
            [
                {
                    "method": "GET",
                    "path": "/fetch-local?url=http%3A%2F%2Flocalhost%40127.0.0.1%3A8001%2Fhealth",
                }
            ],
            _ssrf_candidate(),
        )
        assert len(specs) == 1
