"""Tests for the docker-availability probe in test_container_sandbox.

The probe is evaluated at collection time inside a skipif. If ``docker info``
is slow (loaded DinD daemon on a CI runner) it raises
subprocess.TimeoutExpired, which propagates out of the skipif marker as a
collection ERROR instead of skipping the class. The probe must treat a timeout
(or any subprocess failure) as "docker unavailable" → skip.
"""

from __future__ import annotations

import importlib
import subprocess
from collections.abc import Callable
from typing import Any

import pytest

# Imported by module name (not `from ... import _docker_available`) so the test
# exercises the collection-time probe without tripping reportPrivateUsage on a
# leading-underscore symbol.
tcs = importlib.import_module("tests.unit.test_container_sandbox")
_docker_available: Callable[[], bool] = tcs._docker_available  # type: ignore[attr-defined]


def _which_found(_name: str) -> str:
    return "/usr/bin/docker"


def _which_missing(_name: str) -> None:
    return None


def test_docker_available_returns_false_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A slow `docker info` must yield False (skip), not raise."""

    def _raise_timeout(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(cmd=["docker", "info"], timeout=5)

    monkeypatch.setattr(tcs.shutil, "which", _which_found)
    monkeypatch.setattr(tcs.subprocess, "run", _raise_timeout)
    assert _docker_available() is False


def test_docker_available_returns_false_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    """A `docker info` that exits nonzero (daemon down) must yield False."""

    def _nonzero(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=["docker", "info"], returncode=1)

    monkeypatch.setattr(tcs.shutil, "which", _which_found)
    monkeypatch.setattr(tcs.subprocess, "run", _nonzero)
    assert _docker_available() is False


def test_docker_available_returns_false_when_binary_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No docker binary on PATH must yield False without invoking it."""
    called: list[tuple[Any, ...]] = []

    def _record(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        called.append(args)
        return subprocess.CompletedProcess(args=[], returncode=0)

    monkeypatch.setattr(tcs.shutil, "which", _which_missing)
    monkeypatch.setattr(tcs.subprocess, "run", _record)
    assert _docker_available() is False
    assert called == [], "docker info must not run when the binary is absent"
