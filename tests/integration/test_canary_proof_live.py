"""Live-Docker integration test: Tier-2 canary corroboration.

Exercises the real canary sidecar against a Docker daemon:
  - A callback from an AUTHORIZED target IP (the host, reaching the published
    canary port) with the probe token corroborates.
  - A callback from the sandbox container's own address space is logged but does
    NOT corroborate (source-IP containment, not route-based blocking).

Skipped when Docker is unavailable or no host interface can be pinned.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import shutil
import subprocess
import urllib.request
from collections.abc import Iterator

import pytest

from quarry_activities import sandbox_exec as se
from quarry_workflows.prove_stage import prove_outcome_from_captures

_TOKEN = "0123456789abcdef0123456789abcdef"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _bridge_gateway() -> str | None:
    try:
        proc = subprocess.run(
            [
                "docker",
                "network",
                "inspect",
                "bridge",
                "--format",
                "{{(index .IPAM.Config 0).Gateway}}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    gateway = proc.stdout.strip()
    return gateway or None


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available")


@pytest.fixture
def canary_sidecar(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, str]]:
    """Start a real Tier-2 canary sidecar published on the docker bridge gateway."""
    gateway = _bridge_gateway()
    if gateway is None:
        pytest.skip("no docker bridge gateway to pin the canary host to")
    monkeypatch.setenv("QUARRY_CANARY_HOST", gateway)
    container_id, url = se._start_canary_host(_TOKEN)
    try:
        yield container_id, url
    finally:
        se._collect_canary_logs(container_id)


def _fetch(url: str) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310
        return resp.status, resp.read().decode("utf-8")


def _fetch_from_container(url: str) -> None:
    """Make the request from a throwaway container (the sandbox's address space)."""
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            se.CANARY_DEFAULT_IMAGE,
            "python",
            "-c",
            f"import urllib.request; urllib.request.urlopen({url!r}, timeout=10).read()",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )


def _container_ip(container_id: str) -> str:
    """The canary container's address on the default bridge network."""
    proc = subprocess.run(
        [
            "docker",
            "inspect",
            container_id,
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    ip = proc.stdout.strip()
    assert ip, f"could not read container IP for {container_id}"
    return ip


def test_sidecar_answers_with_token(canary_sidecar: tuple[str, str]) -> None:
    _container_id, url = canary_sidecar
    status, body = _fetch(url)
    assert status == 200
    assert body == f'{{"token": "{_TOKEN}"}}'


def test_authorized_target_callback_corroborates(canary_sidecar: tuple[str, str]) -> None:
    container_id, url = canary_sidecar
    _fetch(url)
    callbacks = se._collect_canary_logs(container_id)
    assert len(callbacks) == 1
    callback = callbacks[0]
    assert _TOKEN in callback.path
    assert callback.source_ip  # the target's observed source address

    verdict = prove_outcome_from_captures(
        [],
        [],
        canary_callbacks=callbacks,
        canary_token=_TOKEN,
        resolved_target_ips=[callback.source_ip],
    )
    assert verdict == "corroborated"


def test_sandbox_ip_callback_is_logged_but_not_corroborated(
    canary_sidecar: tuple[str, str],
) -> None:
    # Authorized target = the host, reaching the published gateway port.
    target_container, target_url = canary_sidecar
    _fetch(target_url)
    target_callbacks = se._collect_canary_logs(target_container)
    assert len(target_callbacks) == 1
    authorized_ip = target_callbacks[0].source_ip

    # The sandbox reaches the canary directly over the bridge (no SNAT), so the
    # callback presents the sandbox container's OWN address — never authorized.
    sandbox_container, _url = se._start_canary_host(_TOKEN)
    try:
        internal_url = (
            f"http://{_container_ip(sandbox_container)}:{se.CANARY_CONTAINER_PORT}/{_TOKEN}"
        )
        _fetch_from_container(internal_url)
        sandbox_callbacks = se._collect_canary_logs(sandbox_container)
        assert len(sandbox_callbacks) == 1
        sandbox_ip = sandbox_callbacks[0].source_ip
        assert sandbox_ip != authorized_ip
        assert _TOKEN in sandbox_callbacks[0].path

        verdict = prove_outcome_from_captures(
            [],
            [],
            canary_callbacks=sandbox_callbacks,
            canary_token=_TOKEN,
            resolved_target_ips=[authorized_ip],
        )
        assert verdict == "not_proved"
    finally:
        se._collect_canary_logs(sandbox_container)
