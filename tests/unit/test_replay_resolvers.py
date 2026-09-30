"""Tests for the replay input resolvers (tasks 1.1–1.6).

Resolvers reconstruct an activity's call arguments from a prior scan's
persisted state (scan DB rows + artifact store). They must fail loudly —
naming the missing input — rather than fabricating a fallback.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.schemas import Provider, VulnerabilityClass
from tests.unit.replay_fixtures import (
    DEFAULT_KB_KEY,
    build_repo,
    build_scan_db,
    make_arch_doc,
    make_candidate,
    make_repository,
    write_kb_artifacts,
    write_ledger_artifact,
)


class TestValidateResolver:
    def test_resolves_candidate_panel_and_repo(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import resolve_validate_inputs

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(tmp_path / "quarry.db", repo, candidates=[finding])
        panel = resolve_validate_inputs(
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            vuln_class="secrets",
        )
        assert panel.candidate.id == finding.id
        assert panel.repo_path == str(repo)
        assert panel.panel.panel_name == "mock"
        assert panel.panel.role_config.provider is Provider.MOCK
        assert panel.panel.role_config.model == "mock-v1"

    def test_class_filter_selects_matching_candidate(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import resolve_validate_inputs

        repo = build_repo(tmp_path)
        secrets_finding = make_candidate("scan-replay-1", vuln_class=VulnerabilityClass.SECRETS)
        idor_finding = make_candidate("scan-replay-1", vuln_class=VulnerabilityClass.IDOR)
        db_path = build_scan_db(
            tmp_path / "quarry.db", repo, candidates=[idor_finding, secrets_finding]
        )
        panel = resolve_validate_inputs(
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            vuln_class="idor",
        )
        assert panel.candidate.id == idor_finding.id

    def test_unknown_scan_fails_loudly(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import ReplayResolutionError, resolve_validate_inputs

        repo = build_repo(tmp_path)
        db_path = build_scan_db(tmp_path / "quarry.db", repo)
        with pytest.raises(ReplayResolutionError, match="scan-replay-missing"):
            resolve_validate_inputs(
                db_path=db_path,
                scan_id="scan-replay-missing",
                repo_path=str(repo),
                vuln_class=None,
            )

    def test_no_candidates_for_class_is_a_named_error(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import ReplayResolutionError, resolve_validate_inputs

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1", vuln_class=VulnerabilityClass.SECRETS)
        db_path = build_scan_db(tmp_path / "quarry.db", repo, candidates=[finding])
        with pytest.raises(ReplayResolutionError, match="idor"):
            resolve_validate_inputs(
                db_path=db_path,
                scan_id="scan-replay-1",
                repo_path=str(repo),
                vuln_class="idor",
            )

    def test_mock_panel_is_rejected_without_mock_flag(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import MockPanelError, resolve_validate_inputs

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(tmp_path / "quarry.db", repo, candidates=[finding])
        # No --mock and the configured panel resolves to mock — refuse, exactly
        # like scripts/replay_validate.py does, so a real spend never hits mock.
        with pytest.raises(MockPanelError, match="mock"):
            resolve_validate_inputs(
                db_path=db_path,
                scan_id="scan-replay-1",
                repo_path=str(repo),
                vuln_class=None,
                allow_mock_panel=False,
            )


class TestHuntResolver:
    def test_reconstructs_task_from_architecture_doc(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import resolve_hunt_inputs

        repo = build_repo(tmp_path)
        arch_doc = make_arch_doc("scan-replay-1")
        db_path = build_scan_db(
            tmp_path / "quarry.db",
            repo,
            vuln_classes=[VulnerabilityClass.SECRETS],
            arch_doc=arch_doc,
        )
        resolved = resolve_hunt_inputs(
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            vuln_class="secrets",
            mock=True,
        )
        task = resolved.task
        assert task.scan_id == "scan-replay-1"
        assert task.vuln_class is VulnerabilityClass.SECRETS
        assert task.role == "hunt"
        assert task.scope == "app"
        assert task.entry_points == arch_doc.subsystems[0].entry_points
        assert resolved.repo_path == str(repo)
        assert resolved.panel.role_config.provider is Provider.MOCK

    def test_carries_kb_root_index_key_from_scan_metadata(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import resolve_hunt_inputs

        repo = build_repo(tmp_path)
        db_path = build_scan_db(
            tmp_path / "quarry.db",
            repo,
            vuln_classes=[VulnerabilityClass.SECRETS],
            arch_doc=make_arch_doc("scan-replay-1"),
            metadata={
                "repo_path": str(repo),
                "kb_root_index_key": DEFAULT_KB_KEY,
            },
        )
        resolved = resolve_hunt_inputs(
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            vuln_class="secrets",
            mock=True,
        )
        assert resolved.kb_root_index_key == DEFAULT_KB_KEY

    def test_missing_arch_doc_is_a_named_error(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import ReplayResolutionError, resolve_hunt_inputs

        repo = build_repo(tmp_path)
        db_path = build_scan_db(tmp_path / "quarry.db", repo)
        with pytest.raises(ReplayResolutionError, match="[Aa]rchitecture"):
            resolve_hunt_inputs(
                db_path=db_path,
                scan_id="scan-replay-1",
                repo_path=str(repo),
                vuln_class="secrets",
                mock=True,
            )


class TestGapfillResolver:
    def test_reconstructs_ledger_tasks_and_findings(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import resolve_gapfill_inputs

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(
            tmp_path / "quarry.db",
            repo,
            vuln_classes=[VulnerabilityClass.SECRETS],
            candidates=[finding],
            metadata={"repo_path": str(repo), "kb_root_index_key": DEFAULT_KB_KEY},
        )
        repository = make_repository(Path(db_path))
        write_ledger_artifact(tmp_path / "artifacts", "scan-replay-1", repository)
        write_kb_artifacts(tmp_path / "artifacts", "scan-replay-1")

        resolved = resolve_gapfill_inputs(
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            artifact_root=str(tmp_path / "artifacts"),
            mock=True,
        )
        assert resolved.ledger.scan_id == "scan-replay-1"
        assert resolved.ledger.vuln_classes_requested == [VulnerabilityClass.SECRETS]
        assert resolved.repo_path == str(repo)
        assert resolved.existing_findings == [
            {
                "vuln_class": "secrets",
                "title": finding.title,
                "affected_component": "app.py:12",
                "root_cause_key": "",
            }
        ]
        assert resolved.kb_root_index_key == DEFAULT_KB_KEY

    def test_missing_coverage_ledger_is_a_named_error(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import ReplayResolutionError, resolve_gapfill_inputs

        repo = build_repo(tmp_path)
        db_path = build_scan_db(tmp_path / "quarry.db", repo)
        with pytest.raises(ReplayResolutionError, match="coverage"):
            resolve_gapfill_inputs(
                db_path=db_path,
                scan_id="scan-replay-1",
                repo_path=str(repo),
                artifact_root=str(tmp_path / "artifacts"),
                mock=True,
            )


class TestProveResolver:
    def test_selects_needs_proof_candidate(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import resolve_prove_inputs

        repo = build_repo(tmp_path)
        candidate = make_candidate("scan-replay-1", status="candidate")
        prove_me = make_candidate("scan-replay-1", status="needs_proof")
        db_path = build_scan_db(tmp_path / "quarry.db", repo, candidates=[candidate, prove_me])
        resolved = resolve_prove_inputs(
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            finding_id=None,
            mock=True,
        )
        assert resolved.candidate.id == prove_me.id
        assert resolved.candidate.status == "needs_proof"

    def test_no_provable_finding_is_a_named_error(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import ReplayResolutionError, resolve_prove_inputs

        repo = build_repo(tmp_path)
        db_path = build_scan_db(tmp_path / "quarry.db", repo)
        with pytest.raises(ReplayResolutionError, match="needs_proof"):
            resolve_prove_inputs(
                db_path=db_path,
                scan_id="scan-replay-1",
                repo_path=str(repo),
                finding_id=None,
                mock=True,
            )


class TestTraceResolver:
    def test_reconstructs_finding_and_call_graph(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import resolve_trace_inputs

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1", vuln_class=VulnerabilityClass.SECRETS)
        db_path = build_scan_db(tmp_path / "quarry.db", repo, candidates=[finding])
        resolved = resolve_trace_inputs(
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            finding_id=finding.id,
            mock=True,
        )
        assert resolved.candidate.id == finding.id
        assert resolved.call_graph.scan_id == "scan-replay-1"
        assert resolved.call_graph.index_kind == "ast_grep"

    def test_unknown_finding_id_is_a_named_error(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import ReplayResolutionError, resolve_trace_inputs

        repo = build_repo(tmp_path)
        db_path = build_scan_db(tmp_path / "quarry.db", repo)
        with pytest.raises(ReplayResolutionError, match="nope"):
            resolve_trace_inputs(
                db_path=db_path,
                scan_id="scan-replay-1",
                repo_path=str(repo),
                finding_id="nope",
                mock=True,
            )


class TestReconResolvers:
    def test_orchestrator_inputs_from_scan(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import resolve_recon_inputs

        repo = build_repo(tmp_path)
        db_path = build_scan_db(tmp_path / "quarry.db", repo)
        resolved = resolve_recon_inputs(
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            sub_index=0,
            mock=True,
        )
        assert resolved.repo_root == str(repo)
        assert resolved.scan_id == "scan-replay-1"
        assert resolved.panel.role_config.provider is Provider.MOCK

    def test_sub_index_beyond_assignments_fails_loudly(self, tmp_path: Path) -> None:
        from quarry_replay.resolvers import ReplayResolutionError, resolve_recon_inputs

        repo = build_repo(tmp_path)
        db_path = build_scan_db(tmp_path / "quarry.db", repo)
        with pytest.raises(ReplayResolutionError, match="subsystem"):
            resolve_recon_inputs(
                db_path=db_path,
                scan_id="scan-replay-1",
                repo_path=str(repo),
                sub_index=5,
                mock=True,
            )


class TestRealPanelResolution:
    def test_named_panel_is_resolved_via_load_quarry_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from quarry_replay.resolvers import resolve_validate_inputs

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(tmp_path / "quarry.db", repo, candidates=[finding])
        (tmp_path / "quarry.toml").write_text(
            """
[panels.chutes.roles.validate]
provider = "litellm"
model = "chutes/Qwen/Qwen3-235B-A22B"
rpm = 20
""",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("QUARRY_PANEL", raising=False)
        resolved = resolve_validate_inputs(
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            vuln_class=None,
            panel_name="chutes",
            allow_mock_panel=True,
        )
        assert resolved.panel.role_config.provider is Provider.LITELLM
        assert resolved.panel.role_config.model == "chutes/Qwen/Qwen3-235B-A22B"
        assert resolved.panel.panel_name == "chutes"


def _now() -> datetime:
    return datetime.now(UTC)
