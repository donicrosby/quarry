"""Tests for the `quarry benchmark cybergym` CLI command."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from quarry_benchmark.cybergym import hf_url
from quarry_benchmark.verifier import CybergymVerdict
from quarry_cli.main import app

runner = CliRunner()
FIXTURE = Path(__file__).parent.parent / "fixtures" / "cybergym" / "mini_tasks.json"


def _level_files_url_map() -> dict[str, bytes]:
    import json as _json

    raw = _json.loads(FIXTURE.read_text(encoding="utf-8"))
    files: dict[str, bytes] = {}
    for task in raw:
        for rel in task["task_difficulty"]["level1"]:
            fname = rel.rsplit("/", 1)[-1]
            if fname == "repo-vul.tar.gz":
                buf = io.BytesIO()
                with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                    info = tarfile.TarInfo("repo/magic.c")
                    payload = b"int x;\n"
                    info.size = len(payload)
                    tar.addfile(info, io.BytesIO(payload))
                files[hf_url(task["task_id"], fname)] = buf.getvalue()
            else:
                files[hf_url(task["task_id"], fname)] = b"description"
    return files


def test_benchmark_cybergym_smoke(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Happy path with injected fakes: artifact written, summary printed."""
    import base64

    import quarry_benchmark.runner as runner_mod
    from quarry_benchmark.agent import ReproductionAttempt
    from quarry_models.mock_client import MockModelClient

    files = _level_files_url_map()

    def fake_fetch(url: str) -> bytes:
        return files[url]

    class _Client(MockModelClient):
        def __init__(self) -> None:
            attempt = ReproductionAttempt(
                poc_base64=base64.b64encode(b"cli-poc").decode(),
                poc_format="fuzzer-input-bytes",
                rationale="r",
            )
            super().__init__(default=attempt)

    monkeypatch.setattr(runner_mod, "httpx_fetch", fake_fetch)
    monkeypatch.setattr(runner_mod, "git_sha", lambda: "deadbeef")
    monkeypatch.setattr(runner_mod, "docker_available", lambda: True)

    def fake_verify(poc: Path, task_id: str, **kwargs: Any) -> CybergymVerdict:
        return CybergymVerdict(vul_exit_code=139, fix_exit_code=0, solved=True)

    monkeypatch.setattr("quarry_benchmark.runner.verify", fake_verify)
    monkeypatch.setattr("quarry_cli.main.LiteLLMModelClient", _Client)

    work = tmp_path / "work"
    result = runner.invoke(
        app,
        [
            "benchmark",
            "cybergym",
            "--manifest",
            str(FIXTURE),
            "--subset",
            "arvo:1065",
            "--level",
            "level1",
            "--work-dir",
            str(work),
            "--max-iterations",
            "2",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "solved=" in result.output
    assert "artifact=" in result.output
    artifacts = list(work.glob("*/result.json"))
    assert len(artifacts) == 1
    data = json.loads(artifacts[0].read_text(encoding="utf-8"))
    assert data["provenance"]["harness_sha"] == "deadbeef"
    assert data["provenance"]["config"]["mode"] == "agent"
    assert data["tasks"][0]["task_id"] == "arvo:1065"
    assert data["tasks"][0]["solved"] is True


def test_benchmark_cybergym_missing_manifest_exits_1(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "benchmark",
            "cybergym",
            "--manifest",
            str(tmp_path / "nope.json"),
            "--level",
            "level1",
            "--work-dir",
            str(tmp_path / "w"),
        ],
    )
    assert result.exit_code == 1
    assert "manifest" in result.output.lower()
