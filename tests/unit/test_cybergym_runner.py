"""Tests for the CyberGym benchmark runner (orchestration + provenance)."""

from __future__ import annotations

import base64
import io
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from quarry.benchmark_artifacts import BenchmarkRunResult
from quarry_benchmark.agent import ReproductionAttempt
from quarry_benchmark.cybergym import OFFICIAL_SUBSET_10, hf_url, load_manifest
from quarry_benchmark.runner import run_cybergym_benchmark

FIXTURE = Path(__file__).parent.parent / "fixtures" / "cybergym" / "mini_tasks.json"


def _level_files(task: Any) -> dict[str, bytes]:
    """Map full HF URLs → bytes for a task's level-1 files (in-memory tar)."""
    files: dict[str, bytes] = {}
    for rel in task.task_difficulty["level1"]:
        fname = rel.rsplit("/", 1)[-1]
        if fname == "repo-vul.tar.gz":
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                info = tarfile.TarInfo("repo/magic.c")
                data = b"int x;\n"
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            files[hf_url(task.task_id, fname)] = buf.getvalue()
        else:
            files[hf_url(task.task_id, fname)] = b"vulnerability description text"
    return files


def _fake_fetch(files: dict[str, bytes]):
    def fetch(url: str) -> bytes:
        if url not in files:
            raise ConnectionError(f"no file for {url}")
        return files[url]

    return fetch


class _FakeClient:
    """complete_structured returns a valid ReproductionAttempt immediately."""

    def __init__(self) -> None:
        self.invocations: list[Any] = []

    def complete_structured(self, request: Any, response_model: Any) -> Any:
        attempt = ReproductionAttempt(
            poc_base64=base64.b64encode(b"agent-poc").decode(),
            poc_format="fuzzer-input-bytes",
            rationale="r",
            target_function=None,
        )

        class _R(BaseModel):
            parsed: Any = None
            content: str = ""

        return _R(parsed=attempt)


class _CrashRunner:
    """Exec runner faking docker: agent poc crashes vul (139), clean on fix (0)."""

    def __call__(self, args: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        vol = args.index("-v")
        image_name = args[vol + 2]
        exit_code = 0 if image_name.endswith("-fix") else 139
        return subprocess.CompletedProcess(args=args, returncode=exit_code, stdout="", stderr="")


class TestRunCybergymBenchmark:
    def test_agent_mode_end_to_end(self, tmp_path: Path) -> None:
        tasks = load_manifest(FIXTURE)
        selected = [t for t in tasks if t.task_id in ("arvo:1065", "oss-fuzz:42535201")]
        files: dict[str, bytes] = {}
        for t in selected:
            files.update(_level_files(t))

        result = run_cybergym_benchmark(
            selected,
            level="level1",
            work_dir=tmp_path / "work",
            harness_sha="abc123",
            client_factory=lambda task_id: _FakeClient(),
            fetch=_fake_fetch(files),
            exec_runner=_CrashRunner(),
            budget_usd=2.0,
            max_iterations=3,
        )
        by_id = {o.task_id: o for o in result.tasks}
        assert set(by_id) == {"arvo:1065", "oss-fuzz:42535201"}
        assert all(o.solved for o in result.tasks)
        assert by_id["arvo:1065"].vul_exit_code == 139
        assert by_id["arvo:1065"].fix_exit_code == 0
        assert result.metrics.proof_rate == pytest.approx(1.0)
        assert result.provenance.harness_sha == "abc123"
        assert result.provenance.config["mode"] == "agent"
        assert result.provenance.config["level"] == "level1"
        assert result.run_id.startswith("cybergym-level1-")
        # artifact round-trips
        artifact = result.save(tmp_path)
        loaded = BenchmarkRunResult.load(artifact)
        assert loaded.run_id == result.run_id
        assert [t.task_id for t in loaded.tasks] == [t.task_id for t in result.tasks]

    def test_verify_only_mode_uses_reference_poc(self, tmp_path: Path) -> None:
        tasks = load_manifest(FIXTURE)
        selected = [t for t in tasks if t.task_id == "arvo:1065"]
        poc_dir = tmp_path / "ref_pocs"
        poc_dir.mkdir()
        (poc_dir / "arvo_1065_poc.bin").write_bytes(b"reference-poc")

        result = run_cybergym_benchmark(
            selected,
            level="level1",
            work_dir=tmp_path / "work",
            harness_sha="abc123",
            client_factory=lambda task_id: _FakeClient(),
            fetch=_fake_fetch(_level_files(selected[0])),
            exec_runner=_CrashRunner(),
            verify_only=True,
            reference_poc_dir=poc_dir,
            budget_usd=2.0,
            max_iterations=3,
        )
        outcome = result.tasks[0]
        assert outcome.solved
        assert result.provenance.config["mode"] == "verify-only"
        # verify-only must not spend model budget
        assert outcome.cost_usd == 0.0
        assert outcome.input_tokens == 0

    def test_missing_reference_poc_records_error_not_crash(self, tmp_path: Path) -> None:
        tasks = load_manifest(FIXTURE)
        selected = [t for t in tasks if t.task_id == "arvo:1065"]
        poc_dir = tmp_path / "ref_pocs"  # exists but empty — no staged poc
        poc_dir.mkdir()

        result = run_cybergym_benchmark(
            selected,
            level="level1",
            work_dir=tmp_path / "work",
            harness_sha="abc123",
            client_factory=lambda task_id: _FakeClient(),
            fetch=_fake_fetch(_level_files(selected[0])),
            exec_runner=_CrashRunner(),
            verify_only=True,
            reference_poc_dir=poc_dir,
            budget_usd=2.0,
            max_iterations=3,
        )
        outcome = result.tasks[0]
        assert not outcome.solved
        assert outcome.error is not None
        assert "reference poc" in outcome.error.lower()

    def test_task_failure_recorded_as_error(self, tmp_path: Path) -> None:
        tasks = load_manifest(FIXTURE)
        selected = [t for t in tasks if t.task_id == "arvo:1065"]

        def boom(task_id: str) -> Any:
            raise RuntimeError("client factory exploded")

        result = run_cybergym_benchmark(
            selected,
            level="level1",
            work_dir=tmp_path / "work",
            harness_sha="abc123",
            client_factory=boom,
            fetch=_fake_fetch(_level_files(selected[0])),
            exec_runner=_CrashRunner(),
            budget_usd=2.0,
            max_iterations=3,
        )
        outcome = result.tasks[0]
        assert not outcome.solved
        assert outcome.error is not None
        assert "exploded" in outcome.error
        assert outcome.vul_exit_code is None
        assert result.metrics.proof_rate == pytest.approx(0.0)

    def test_official_subset_constant(self) -> None:
        assert len(OFFICIAL_SUBSET_10) == 10
        assert "arvo:1065" in OFFICIAL_SUBSET_10
        assert "oss-fuzz:42535201" in OFFICIAL_SUBSET_10
