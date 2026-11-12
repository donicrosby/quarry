"""Tests for the replay runner: direct activity invocation, replay-tagged
invocation recording, the read-only guarantee, and --mock mode (tasks 2.1–2.6).
"""

from __future__ import annotations

import json
from pathlib import Path

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


def _snapshot(db_path: str) -> dict[str, object]:
    repository = make_repository(Path(db_path))
    return {
        "scan": repository.load_scan("scan-replay-1").model_dump_json(),
        "candidates": [
            f.model_dump_json() for f in repository.load_candidate_findings("scan-replay-1")
        ],
        "events": [e.model_dump_json() for e in repository.load_events("scan-replay-1")],
        "invocations": repository.load_model_invocations("scan-replay-1"),
        "traces": repository.load_traces("scan-replay-1"),
        "finals": repository.load_final_findings("scan-replay-1"),
    }


class TestReplayRunnerValidate:
    def test_invokes_activity_and_prints_result(self, tmp_path: Path, capsys: object) -> None:
        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(tmp_path / "quarry.db", repo, candidates=[finding])
        result = run_replay(
            stage="validate",
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            mock=True,
        )
        assert result["stage"] == "validate"
        assert result["mode"] == "mock"
        assert result["panel"] == "mock"
        assert result["scan_id"] == "scan-replay-1"
        assert isinstance(result["result"], dict)
        # validate_activity returns a ValidationResult dict.
        assert result["result"]["candidate_finding_id"] == finding.id
        assert result["result"]["verdict"] in {
            "validated",
            "rejected",
            "needs_proof",
            "inconclusive",
        }

    def test_mock_makes_no_network_call(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        from quarry_replay import runner

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(tmp_path / "quarry.db", repo, candidates=[finding])
        with patch("quarry_models.factory.build_model_client") as mock_build:
            runner.run_replay(
                stage="validate",
                db_path=db_path,
                scan_id="scan-replay-1",
                repo_path=str(repo),
                mock=True,
            )
        mock_build.assert_not_called()

    def test_mock_replay_records_replay_tagged_invocations(self, tmp_path: Path) -> None:
        """Replay-tagged recording: the activity is invoked with db_path=None
        (nothing written to the scan DB), and the invocations its mock client
        recorded come back in the envelope re-tagged as replay."""
        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(tmp_path / "quarry.db", repo, candidates=[finding])
        envelope = run_replay(
            stage="validate",
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            mock=True,
        )
        assert envelope["invocations"], "mock client recorded invocations must be captured"
        for row in envelope["invocations"]:
            assert row["workspace_id"] == "replay"
            assert row["task_name"].startswith("replay:mock:validate")
            assert row["metadata"]["replay"] is True
            assert row["metadata"]["replay_panel"] == "mock"
            assert row["metadata"]["replay_scan_id"] == "scan-replay-1"


class TestReplayReadOnly:
    def test_validate_replay_leaves_scan_state_untouched(self, tmp_path: Path) -> None:
        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(
            tmp_path / "quarry.db", repo, candidates=[finding], metadata={"repo_path": str(repo)}
        )
        before = _snapshot(db_path)
        run_replay(
            stage="validate",
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            mock=True,
        )
        after = _snapshot(db_path)
        assert before == after

    def test_hunt_replay_leaves_scan_state_untouched(self, tmp_path: Path) -> None:
        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        db_path = build_scan_db(
            tmp_path / "quarry.db",
            repo,
            vuln_classes=["secrets"],
            arch_doc=make_arch_doc("scan-replay-1"),
            metadata={"repo_path": str(repo), "kb_root_index_key": DEFAULT_KB_KEY},
        )
        write_kb_artifacts(tmp_path / "artifacts", "scan-replay-1")
        before = _snapshot(db_path)
        run_replay(
            stage="hunt",
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            artifact_root=str(tmp_path / "artifacts"),
            mock=True,
        )
        assert before == _snapshot(db_path)


class TestReplayRunnerAllStages:
    """Every stage's runner path resolves inputs, runs the activity, and
    returns a structurally valid result under the mock panel (dry-run for
    the golden shape checks; full asserts live in the golden tests)."""

    def test_hunt_result_shape(self, tmp_path: Path) -> None:
        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        db_path = build_scan_db(
            tmp_path / "quarry.db",
            repo,
            vuln_classes=["secrets"],
            arch_doc=make_arch_doc("scan-replay-1"),
            metadata={"repo_path": str(repo)},
        )
        result = run_replay(
            stage="hunt",
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            mock=True,
        )
        assert result["stage"] == "hunt"
        assert isinstance(result["result"], dict)
        assert "findings" in result["result"]
        assert "coverage_gaps" in result["result"]
        assert result["result"]["task"]["scan_id"] == "scan-replay-1"

    def test_gapfill_result_shape(self, tmp_path: Path) -> None:
        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(
            tmp_path / "quarry.db",
            repo,
            vuln_classes=["secrets"],
            candidates=[finding],
            metadata={"repo_path": str(repo)},
        )
        artifacts = tmp_path / "artifacts"
        write_ledger_artifact(artifacts, "scan-replay-1", make_repository(Path(db_path)))
        result = run_replay(
            stage="gapfill",
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            artifact_root=str(artifacts),
            mock=True,
        )
        assert result["stage"] == "gapfill"
        assert isinstance(result["result"], list)

    def test_prove_result_shape(self, tmp_path: Path) -> None:
        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        prove_me = make_candidate("scan-replay-1", status="needs_proof")
        db_path = build_scan_db(
            tmp_path / "quarry.db", repo, candidates=[prove_me], metadata={"repo_path": str(repo)}
        )
        result = run_replay(
            stage="prove",
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            mock=True,
        )
        assert result["stage"] == "prove"
        assert result["result"]["verdict"] == "inconclusive"  # ProveResponse default

    def test_trace_result_shape(self, tmp_path: Path) -> None:
        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(
            tmp_path / "quarry.db", repo, candidates=[finding], metadata={"repo_path": str(repo)}
        )
        result = run_replay(
            stage="trace",
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            mock=True,
        )
        assert result["stage"] == "trace"
        assert result["result"]["finding_id"] == finding.id
        assert result["result"]["reachable"] in {"reachable", "not_reachable", "indeterminate"}

    def test_recon_result_shape(self, tmp_path: Path) -> None:
        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        db_path = build_scan_db(tmp_path / "quarry.db", repo, metadata={"repo_path": str(repo)})
        result = run_replay(
            stage="recon",
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            sub_index=0,
            mock=True,
        )
        assert result["stage"] == "recon"
        assert result["result"]["name"]  # Subsystem payload has a name

    def test_header_lines_label_mock_mode(self, tmp_path: Path) -> None:
        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(tmp_path / "quarry.db", repo, candidates=[finding])
        result = run_replay(
            stage="validate",
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            mock=True,
        )
        header = result["header"]
        assert any("mode=mock" in line for line in header)
        assert any("replay=1" in line for line in header)

    def test_unknown_stage_raises(self, tmp_path: Path) -> None:
        import pytest

        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        db_path = build_scan_db(tmp_path / "quarry.db", repo)
        with pytest.raises(ValueError, match="unknown stage"):
            run_replay(
                stage="transmogrify",
                db_path=db_path,
                scan_id="scan-replay-1",
                repo_path=str(repo),
                mock=True,
            )

    def test_json_payload_round_trip(self, tmp_path: Path) -> None:
        """The whole runner envelope must be JSON-serialisable (CLI prints it)."""
        from quarry_replay.runner import run_replay

        repo = build_repo(tmp_path)
        finding = make_candidate("scan-replay-1")
        db_path = build_scan_db(tmp_path / "quarry.db", repo, candidates=[finding])
        result = run_replay(
            stage="validate",
            db_path=db_path,
            scan_id="scan-replay-1",
            repo_path=str(repo),
            mock=True,
        )
        encoded = json.dumps(result, default=str)
        assert "mode=mock" in encoded
