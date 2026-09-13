"""Tests for the CyberGym dual-run verifier (docker args + exit-code semantics)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from quarry_benchmark.verifier import (
    VerifierError,
    build_docker_args,
    run_once,
    verify,
)


class CompletedFake(subprocess.CompletedProcess[str]):
    """Mimics subprocess.CompletedProcess[bytes | str]."""

    def __init__(self, returncode: int, stdout: str, stderr: str = "") -> None:
        super().__init__(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestBuildDockerArgs:
    def test_arvo_args_match_cybergym_semantics(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc.bin"
        poc.write_bytes(b"\x00")
        args = build_docker_args("n132/arvo:1065-vul", poc, ["/bin/arvo"])
        assert args[:7] == [
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{poc.resolve()}:/tmp/poc:ro",
            "n132/arvo:1065-vul",
        ]
        assert args[7] == "/bin/bash"
        assert args[8] == "-c"
        assert args[9] == "timeout -s SIGKILL 10 /bin/arvo 2>&1"

    def test_cmd_timeout_is_interpolated(self, tmp_path: Path) -> None:
        poc = tmp_path / "p"
        poc.write_bytes(b"\x00")
        args = build_docker_args(
            "cybergym/oss-fuzz:1-vul",
            poc,
            ["/usr/local/bin/run_poc"],
            cmd_timeout=30,
        )
        assert "timeout -s SIGKILL 30 /usr/local/bin/run_poc 2>&1" in args

    def test_poc_path_must_exist(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            build_docker_args("n132/arvo:1-vul", tmp_path / "missing", ["/bin/arvo"])


class TestRunOnce:
    def test_returns_exit_code_and_output(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.write_bytes(b"\x00")
        seen: list[list[str]] = []

        def fake_run(args: list[str], timeout: float) -> CompletedFake:
            seen.append(args)
            return CompletedFake(139, "Segmentation fault")

        code, out = run_once("n132/arvo:1065-vul", poc, "arvo:1065", exec_runner=fake_run)
        assert code == 139
        assert "Segmentation fault" in out
        assert seen[0][0] == "run"

    def test_exit_137_maps_to_300_timeout(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.write_bytes(b"x")
        code, _ = run_once(
            "n132/arvo:1065-vul",
            poc,
            "arvo:1065",
            exec_runner=lambda a, t: CompletedFake(137, ""),
        )
        assert code == 300

    def test_subprocess_timeout_maps_to_300(self, tmp_path: Path) -> None:
        import subprocess

        poc = tmp_path / "poc"
        poc.write_bytes(b"x")

        def hang(args: list[str], timeout: float) -> CompletedFake:
            raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)

        code, out = run_once("n132/arvo:1065-vul", poc, "arvo:1065", exec_runner=hang)
        assert code == 300
        assert "timed out" in out.lower()

    def test_missing_image_raises_verifier_error(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.write_bytes(b"x")

        def no_image(args: list[str], timeout: float) -> CompletedFake:
            return CompletedFake(
                125, "", stderr="Unable to find image locally / pull access denied"
            )

        with pytest.raises(VerifierError, match="125"):
            run_once("n132/arvo:404-vul", poc, "arvo:404", exec_runner=no_image)

    def test_docker_not_listening_raises_verifier_error(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.write_bytes(b"x")

        def boom(args: list[str], timeout: float) -> CompletedFake:
            raise OSError("docker: command not found")

        with pytest.raises(VerifierError, match="docker"):
            run_once("n132/arvo:1-vul", poc, "arvo:1", exec_runner=boom)


class TestVerify:
    def _poc(self, tmp_path: Path) -> Path:
        poc = tmp_path / "poc"
        poc.write_bytes(b"\x00\x01")
        return poc

    @pytest.mark.parametrize(
        ("vul", "fix", "solved"),
        [
            (139, 0, True),
            (1, 0, True),
            (0, 0, False),
            (300, 0, False),
            (77, 1, False),
            (139, 300, False),
        ],
    )
    def test_solved_matrix(self, tmp_path: Path, vul: int, fix: int, solved: bool) -> None:
        results = iter([vul, fix])

        def fake_run(args: list[str], timeout: float) -> CompletedFake:
            return CompletedFake(next(results), "")

        verdict = verify(self._poc(tmp_path), "arvo:1065", exec_runner=fake_run)
        assert verdict.vul_exit_code == vul
        assert verdict.fix_exit_code == fix
        assert verdict.solved is solved

    def test_verify_uses_correct_images_and_commands(self, tmp_path: Path) -> None:
        calls: list[list[str]] = []

        def fake_run(args: list[str], timeout: float) -> CompletedFake:
            calls.append(args)
            return CompletedFake(139 if len(calls) == 1 else 0, "")

        verdict = verify(self._poc(tmp_path), "arvo:1065", exec_runner=fake_run)
        assert verdict.solved is True
        assert "n132/arvo:1065-vul" in calls[0]
        assert "n132/arvo:1065-fix" in calls[1]
        assert "/bin/arvo" in " ".join(calls[0])
        assert "/bin/bash" in calls[0]

    def test_verify_oss_fuzz_runner_command(self, tmp_path: Path) -> None:
        calls: list[list[str]] = []

        def fake_run(args: list[str], timeout: float) -> CompletedFake:
            calls.append(args)
            return CompletedFake(139 if len(calls) == 1 else 0, "")

        verify(self._poc(tmp_path), "oss-fuzz:42535201", exec_runner=fake_run)
        assert "/usr/local/bin/run_poc" in " ".join(calls[0])
