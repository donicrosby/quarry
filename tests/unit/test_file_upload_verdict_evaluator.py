"""File-upload per-class dynamic evaluator: the upload→fetch-back CHAIN.

Written RED first — fails until ``file_upload_evaluator`` exists in
``src/quarry_activities/verdict_evaluators.py`` and ``FILE_UPLOAD`` is
registered with ``min_probes=2``.

Locked contracts:

- ``file_upload_evaluator`` (registered under ``FILE_UPLOAD`` with
  ``min_probes=2``) corroborates only when BOTH chain steps are observed: the
  multipart upload was ACCEPTED (2xx) AND the stored artifact was served back
  (2xx with a non-empty body).  The upload's 2xx alone is never corroboration —
  a 2xx that is never read back proves nothing.
- Registration: FILE_UPLOAD routes per-class on module import and needs a probe
  PAIR (upload + fetch-back) — ``differential_baseline_permitted`` admits the
  fetch-back probe, and ``select_dynamic_probe_specs`` keeps BOTH the agent's
  upload and fetch-back proposals instead of silently dropping the fetch-back
  (the defect this file pins).
"""

from __future__ import annotations

from collections.abc import Generator
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
from quarry_activities.verdict_evaluators import LiveProbeEvidence
from quarry_workflows.run_scan import (
    differential_baseline_permitted,
    select_dynamic_probe_specs,
)

_NOW = datetime(2026, 6, 13, tzinfo=UTC)
_SCAN_ID = "scan-file-upload-eval"


@pytest.fixture(autouse=True)
def builtin_evaluators_registered() -> Generator[None, None, None]:
    """Ensure the builtin evaluators are registered regardless of test order."""
    from quarry_activities.verdict_evaluators import register_builtin_evaluators

    register_builtin_evaluators()
    yield
    register_builtin_evaluators()


# Referenced so pyright's reportUnusedFunction does not fire on the fixture.
_FIXTURES = (builtin_evaluators_registered,)


def _file_upload_candidate() -> CandidateFinding:
    return CandidateFinding(
        id="cf-file-upload-eval-1",
        scan_id=_SCAN_ID,
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.FILE_UPLOAD,
        title="Unrestricted upload on /upload",
        hypothesis="The handler stores the client-supplied filename with no allow-list.",
        affected_component="app.py:58",
        root_cause_key="file-upload-stored-name",
        hunter_provider="mock",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
        source_refs=[
            SourceRef(
                file_path="app.py",
                start_line=58,
                end_line=66,
                symbol="upload",
            )
        ],
        status=FindingStatus.NEEDS_PROOF,
    )


def _fetch_back(status_code: int, body_text: str | None) -> LiveProbeEvidence:
    return LiveProbeEvidence(status_code=status_code, body_text=body_text)


# ---------------------------------------------------------------------------
# file_upload_evaluator — every branch
# ---------------------------------------------------------------------------


class TestFileUploadEvaluator:
    def test_upload_and_fetch_back_observed_corroborates(self) -> None:
        """Both chain steps 2xx and the fetch-back serves the stored bytes."""
        from quarry_activities.verdict_evaluators import file_upload_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text='{"stored": "/uploads/probe.php", "extension": ".php"}',
            additional=(_fetch_back(200, '{"content": "QRYMARKER"}'),),
        )
        assert file_upload_evaluator(ev) == "corroborated"

    def test_upload_only_inconclusive(self) -> None:
        """No fetch-back → the chain cannot decide, even on a 2xx upload."""
        from quarry_activities.verdict_evaluators import file_upload_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text='{"stored": "/uploads/probe.php"}',
        )
        assert file_upload_evaluator(ev) == "inconclusive"

    @pytest.mark.parametrize("status_code", [400, 403, 404, 415, 422])
    def test_upload_rejected_not_corroborated(self, status_code: int) -> None:
        """The handler enforced the extension/content-type rule the candidate
        claims is missing → the hypothesis is refuted."""
        from quarry_activities.verdict_evaluators import file_upload_evaluator

        ev = LiveProbeEvidence(
            status_code=status_code,
            body_text='{"detail": "extension not allowed"}',
            additional=(_fetch_back(404, None),),
        )
        assert file_upload_evaluator(ev) == "not_corroborated"

    @pytest.mark.parametrize("status_code", [500, 502, 302])
    def test_upload_other_non_2xx_inconclusive(self, status_code: int) -> None:
        """A server fault / unexpected status is not a defence → cannot decide."""
        from quarry_activities.verdict_evaluators import file_upload_evaluator

        ev = LiveProbeEvidence(
            status_code=status_code,
            body_text="Internal Server Error",
            additional=(_fetch_back(200, "QRYMARKER"),),
        )
        assert file_upload_evaluator(ev) == "inconclusive"

    @pytest.mark.parametrize("status_code", [400, 403, 404])
    def test_fetch_back_not_served_not_corroborated(self, status_code: int) -> None:
        """Upload accepted but the stored artifact is not read back → refuted."""
        from quarry_activities.verdict_evaluators import file_upload_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text='{"stored": "/uploads/probe.php"}',
            additional=(_fetch_back(status_code, '{"detail": "not found"}'),),
        )
        assert file_upload_evaluator(ev) == "not_corroborated"

    @pytest.mark.parametrize("status_code", [500, 502])
    def test_fetch_back_server_error_inconclusive(self, status_code: int) -> None:
        from quarry_activities.verdict_evaluators import file_upload_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text='{"stored": "/uploads/probe.php"}',
            additional=(_fetch_back(status_code, "boom"),),
        )
        assert file_upload_evaluator(ev) == "inconclusive"

    def test_fetch_back_unresolvable_body_inconclusive(self) -> None:
        from quarry_activities.verdict_evaluators import file_upload_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text='{"stored": "/uploads/probe.php"}',
            additional=(_fetch_back(200, None),),
        )
        assert file_upload_evaluator(ev) == "inconclusive"

    def test_fetch_back_empty_body_not_corroborated(self) -> None:
        """A 2xx with nothing read back is no evidence the file was served."""
        from quarry_activities.verdict_evaluators import file_upload_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text='{"stored": "/uploads/probe.php"}',
            additional=(_fetch_back(200, "   "),),
        )
        assert file_upload_evaluator(ev) == "not_corroborated"

    def test_extra_probes_beyond_fetch_back_ignored(self) -> None:
        from quarry_activities.verdict_evaluators import file_upload_evaluator

        ev = LiveProbeEvidence(
            status_code=200,
            body_text='{"stored": "/uploads/probe.php"}',
            additional=(
                _fetch_back(200, "QRYMARKER"),
                _fetch_back(500, "unrelated"),
            ),
        )
        assert file_upload_evaluator(ev) == "corroborated"


# ---------------------------------------------------------------------------
# Registration hygiene: FILE_UPLOAD routes per-class after import, needs a CHAIN
# ---------------------------------------------------------------------------


class TestFileUploadRegistration:
    def test_module_import_registers_file_upload_evaluator(self) -> None:
        """A FRESH interpreter import registers FILE_UPLOAD.  The subprocess
        pins PYTHONPATH to THIS repo's src/ so it tests this checkout even when
        a sibling editable install of quarry sits in site-packages."""
        import os
        import subprocess
        import sys
        from pathlib import Path

        repo_src = str(Path(__file__).resolve().parents[2] / "src")
        code = (
            "from quarry.schemas import VulnerabilityClass\n"
            "import quarry_activities.verdict_evaluators as ve\n"
            "fu = VulnerabilityClass.FILE_UPLOAD\n"
            "assert ve.resolve_evaluator(fu) is ve.file_upload_evaluator\n"
            "assert ve.resolve_evaluator_spec(fu).min_probes == 2\n"
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

    def test_file_upload_resolves_with_min_probes_two(self) -> None:
        from quarry_activities.verdict_evaluators import (
            file_upload_evaluator,
            resolve_evaluator,
            resolve_evaluator_spec,
        )

        assert resolve_evaluator(VulnerabilityClass.FILE_UPLOAD) is file_upload_evaluator
        assert resolve_evaluator_spec(VulnerabilityClass.FILE_UPLOAD).min_probes == 2

    def test_file_upload_routes_per_class_with_source_tag(self) -> None:
        from quarry_activities.verdict_evaluators import evaluate_live_verdict_with_source

        ev = LiveProbeEvidence(
            status_code=200,
            body_text='{"stored": "/uploads/probe.php"}',
            additional=(_fetch_back(200, "QRYMARKER"),),
        )
        assert evaluate_live_verdict_with_source(VulnerabilityClass.FILE_UPLOAD, ev) == (
            "corroborated",
            "per_class",
        )

    def test_file_upload_baseline_permitted_with_uncapped_budget(self) -> None:
        assert differential_baseline_permitted(
            VulnerabilityClass.FILE_UPLOAD, budget_remaining=None
        )

    def test_file_upload_baseline_refused_without_budget(self) -> None:
        assert not differential_baseline_permitted(
            VulnerabilityClass.FILE_UPLOAD, budget_remaining=0.0
        )


# ---------------------------------------------------------------------------
# Dispatch through select_dynamic_probe_specs — the S1 fix surface
# ---------------------------------------------------------------------------


class TestSelectDynamicProbeSpecsFileUpload:
    def test_upload_and_fetch_back_proposals_both_selected(self) -> None:
        """FILE_UPLOAD (min_probes=2) keeps BOTH the multipart upload and its
        fetch-back — the defect was that the fetch-back was silently dropped."""
        specs = select_dynamic_probe_specs(
            [
                {
                    "method": "POST",
                    "path": "/upload",
                    "multipart_fields": [
                        {
                            "name": "file",
                            "value": "QRYMARKER",
                            "filename": "probe.php",
                            "content_type": "text/plain",
                        }
                    ],
                },
                {"method": "GET", "path": "/uploads/probe.php"},
            ],
            _file_upload_candidate(),
        )
        assert [spec.method for spec in specs] == ["POST", "GET"]
        assert specs[0].path == "/upload"
        assert specs[0].multipart_fields  # the multipart upload part survives selection
        assert specs[1].path == "/uploads/probe.php"
        for spec in specs:
            assert spec.auth_profile is None

    def test_upload_only_proposal_dispatches_one(self) -> None:
        """Only the upload proposed → one spec (no guessed fetch-back path);
        the evaluator then reads the missing step as inconclusive, never a
        false corroboration from the upload's 2xx alone."""
        specs = select_dynamic_probe_specs(
            [{"method": "POST", "path": "/upload"}],
            _file_upload_candidate(),
        )
        assert len(specs) == 1
        assert specs[0].path == "/upload"
