"""Tests for the mitigation_stretching deterministic backstop.

Run-5 regression: the debater rejected a genuine `shell=True` cmdi with a
mitigation_stretching FAIL citing `app.py:74-78` — where the only code is
`timeout=3` / `capture_output=True` / `check=False`. None of those are
mitigations. The gate must refuse to let that FAIL drive a rejection.
"""

from __future__ import annotations

from pathlib import Path

from quarry.schemas import ChecklistConstraint, ChecklistItem, ChecklistOutcome
from quarry_models.mitigation_gate import sanitize_checklist_fails


def _item(
    constraint: ChecklistConstraint,
    outcome: ChecklistOutcome,
    evidence: str = "",
) -> ChecklistItem:
    return ChecklistItem(constraint=constraint, outcome=outcome, evidence=evidence)


class TestMitigationGate:
    def test_run5_signature_downgraded_to_unresolved(self) -> None:
        """The exact run-5 cmdi failure: timeout/capture_output cited as the
        'mitigation' for a shell=True command injection."""
        items = [
            _item(
                ChecklistConstraint.MITIGATION_STRETCHING,
                ChecklistOutcome.FAIL,
                "app.py:74-78 (timeout=3, capture_output=True, check=False)",
            )
        ]
        out = sanitize_checklist_fails(items)
        assert out[0].outcome is ChecklistOutcome.UNRESOLVED
        assert "gate: FAIL unsupported" in out[0].evidence

    def test_bare_location_with_no_primitive_downgraded(self) -> None:
        items = [
            _item(
                ChecklistConstraint.MITIGATION_STRETCHING,
                ChecklistOutcome.FAIL,
                "app.py:52",
            )
        ]
        out = sanitize_checklist_fails(items)
        assert out[0].outcome is ChecklistOutcome.UNRESOLVED

    def test_real_sanitizer_fail_stands(self) -> None:
        """A FAIL that names an actual sanitizer is credible — keep it."""
        items = [
            _item(
                ChecklistConstraint.MITIGATION_STRETCHING,
                ChecklistOutcome.FAIL,
                "app.py:40-44 — shlex.quote(host) sanitizes the value before the sink",
            )
        ]
        out = sanitize_checklist_fails(items)
        assert out[0].outcome is ChecklistOutcome.FAIL

    def test_allowlist_fail_stands(self) -> None:
        items = [
            _item(
                ChecklistConstraint.MITIGATION_STRETCHING,
                ChecklistOutcome.FAIL,
                "app.py:31 — allowlist check rejects hosts outside {localhost, 127.0.0.1}",
            )
        ]
        out = sanitize_checklist_fails(items)
        assert out[0].outcome is ChecklistOutcome.FAIL

    def test_other_constraints_untouched(self) -> None:
        """The gate only applies to mitigation_stretching."""
        items = [
            _item(
                ChecklistConstraint.PEDANTIC_LINTING,
                ChecklistOutcome.FAIL,
                "app.py:13 — placeholder value",
            )
        ]
        out = sanitize_checklist_fails(items)
        assert out[0].outcome is ChecklistOutcome.FAIL
        assert out[0].evidence == "app.py:13 — placeholder value"

    def test_pass_and_not_applicable_untouched(self) -> None:
        items = [
            _item(ChecklistConstraint.MITIGATION_STRETCHING, ChecklistOutcome.PASS, ""),
            _item(ChecklistConstraint.SOURCE_COHERENCE, ChecklistOutcome.NOT_APPLICABLE, ""),
        ]
        out = sanitize_checklist_fails(items)
        assert [i.outcome for i in out] == [
            ChecklistOutcome.PASS,
            ChecklistOutcome.NOT_APPLICABLE,
        ]

    def test_mixed_checklist_only_stretched_item_downgraded(self) -> None:
        items = [
            _item(ChecklistConstraint.SOURCE_COHERENCE, ChecklistOutcome.PASS, "app.py:74"),
            _item(
                ChecklistConstraint.MITIGATION_STRETCHING,
                ChecklistOutcome.FAIL,
                "app.py:74-78 (timeout)",
            ),
            _item(ChecklistConstraint.TRUST_BOUNDARY, ChecklistOutcome.FAIL, "app.py:1"),
        ]
        out = sanitize_checklist_fails(items)
        assert out[0].outcome is ChecklistOutcome.PASS
        assert out[1].outcome is ChecklistOutcome.UNRESOLVED
        assert out[2].outcome is ChecklistOutcome.FAIL


class TestCoherenceGate:
    def test_lazy_coherence_fail_on_existing_file_downgraded(self, tmp_path: Path) -> None:
        """Run-5 signature: debater FAILs source_coherence on app.py:74 with no
        explanation; the file exists. Gate downgrades to unresolved."""
        (tmp_path / "app.py").write_text("import subprocess\n" * 80)
        items = [_item(ChecklistConstraint.SOURCE_COHERENCE, ChecklistOutcome.FAIL, "app.py:74")]
        out = sanitize_checklist_fails(items, repo_root=tmp_path)
        assert out[0].outcome is ChecklistOutcome.UNRESOLVED
        assert "cited file(s) exist" in out[0].evidence

    def test_coherence_fail_with_mismatch_marker_stands(self, tmp_path: Path) -> None:
        """A coherence FAIL that names a concrete mismatch is credible."""
        (tmp_path / "app.py").write_text("x = 1\n")
        items = [
            _item(
                ChecklistConstraint.SOURCE_COHERENCE,
                ChecklistOutcome.FAIL,
                "app.py:74 — no code found at cited location",
            )
        ]
        out = sanitize_checklist_fails(items, repo_root=tmp_path)
        assert out[0].outcome is ChecklistOutcome.FAIL

    def test_coherence_fail_on_missing_file_stands(self, tmp_path: Path) -> None:
        items = [
            _item(
                ChecklistConstraint.SOURCE_COHERENCE,
                ChecklistOutcome.FAIL,
                "lib/missing.py:12",
            )
        ]
        out = sanitize_checklist_fails(items, repo_root=tmp_path)
        assert out[0].outcome is ChecklistOutcome.FAIL

    def test_coherence_untouched_without_repo_root(self) -> None:
        items = [_item(ChecklistConstraint.SOURCE_COHERENCE, ChecklistOutcome.FAIL, "app.py:74")]
        out = sanitize_checklist_fails(items)
        assert out[0].outcome is ChecklistOutcome.FAIL
