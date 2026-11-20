"""build_sandbox_backend: env-driven backend / image / memory selection (ADR-024 §A).

Pins that the sandbox knobs are actually READ by the path they steer — a new
config field that is only validated but never consumed is a dead knob.  Here we
drive ``QUARRY_SANDBOX_MEMORY`` end to end and assert the resulting value reaches
the ``docker run`` argv, so the browser-capable worker's container cap is
configurable from the environment (browser-worker-playwright tasks.md 5.2).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from quarry.schemas import SandboxExecSpec
from quarry_activities.sandbox import DEFAULT_MEMORY_LIMIT, ContainerSandbox
from quarry_activities.sandbox_exec import build_sandbox_backend


def _spec() -> SandboxExecSpec:
    return SandboxExecSpec(command="echo", args=["hi"])


def _run_argv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[str]:
    """Build the backend from the current env, run it, return the docker-run argv."""
    sb = build_sandbox_backend()
    assert isinstance(sb, ContainerSandbox)
    proc = MagicMock(stdout="ok", stderr="", returncode=0)
    with patch("subprocess.run", return_value=proc) as mock_run:
        sb.run(_spec(), work_dir=tmp_path, resolved_env={}, egress_policy=None)
    return [str(part) for part in mock_run.call_args[0][0]]


def test_container_backend_defaults_to_the_module_memory_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With no QUARRY_SANDBOX_MEMORY the ContainerSandbox default cap applies."""
    monkeypatch.setenv("QUARRY_SANDBOX_BACKEND", "container")
    monkeypatch.delenv("QUARRY_SANDBOX_MEMORY", raising=False)

    argv = _run_argv(monkeypatch, tmp_path)
    assert argv[argv.index("--memory") + 1] == DEFAULT_MEMORY_LIMIT


def test_quarry_sandbox_memory_reaches_docker_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """QUARRY_SANDBOX_MEMORY is consumed at run time and lands in the docker argv."""
    monkeypatch.setenv("QUARRY_SANDBOX_BACKEND", "container")
    monkeypatch.setenv("QUARRY_SANDBOX_MEMORY", "768m")

    argv = _run_argv(monkeypatch, tmp_path)
    assert argv[argv.index("--memory") + 1] == "768m"
    assert argv[argv.index("--memory-swap") + 1] == "768m"
