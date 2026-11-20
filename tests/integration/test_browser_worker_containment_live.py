"""Live-Docker containment probe for the browser-capable (dynamic) worker.

Acceptance criterion (t_fbe652c1 / browser-worker-playwright tasks.md 5.2, 6.3):
a browser-capable container run with a target endpoint set (a non-empty egress
policy) cannot reach an unlisted host — kernel-enforced network isolation — and
runs under a container memory cap enforced by the kernel (cgroup ``memory.max``).

These tests exercise the Tier-2 ``ContainerSandbox`` against a real Docker daemon
using the browser-capable image (``quarry:dynamic``; locally ``quarry:dynamic-verify``
is accepted).  The whole module is skipped when Docker is unavailable or no
browser-capable image is present, and the image can be pinned with
``QUARRY_BROWSER_IMAGE``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from quarry.schemas import (
    ResolvedDestinationSet,
    ResolvedEgressPolicy,
    SandboxExecSpec,
)
from quarry_activities.sandbox import ContainerSandbox, egress_network_name

LISTENER_IMAGE = "alpine:3.20"
BROWSER_IMAGE_CANDIDATES = ("quarry:dynamic", "quarry:dynamic-verify")
MEMORY_LIMIT = "256m"
MEMORY_LIMIT_BYTES = 256 * 1024 * 1024

EgressEnv = tuple[ResolvedEgressPolicy, dict[str, str]]


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _image_present(image: str) -> bool:
    try:
        return (
            subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True,
                timeout=15,
            ).returncode
            == 0
        )
    except (subprocess.TimeoutExpired, OSError):
        return False


def _browser_image() -> str | None:
    override = os.environ.get("QUARRY_BROWSER_IMAGE", "").strip()
    if override:
        return override if _image_present(override) else None
    for candidate in BROWSER_IMAGE_CANDIDATES:
        if _image_present(candidate):
            return candidate
    return None


pytestmark = [
    pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available"),
    pytest.mark.skipif(_browser_image() is None, reason="no browser-capable image present"),
]


def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)  # type: ignore[arg-type]


def _policy(ips: dict[str, str]) -> ResolvedEgressPolicy:
    return ResolvedEgressPolicy(
        destination_sets=[
            ResolvedDestinationSet(name=name, allowed_ips=[ip]) for name, ip in ips.items()
        ]
    )


def _listener_cmd(body: str, port: int) -> str:
    """Shell one-liner: answer every TCP connection with a fixed body."""
    head = "HTTP/1.1 200 OK\\r\\nContent-Length: 6\\r\\n\\r\\n"
    return f"while true; do printf '{head}{body}' | nc -l -p {port}; done"


def _fetch_spec(ip: str, port: int) -> SandboxExecSpec:
    """Python urllib probe — the browser image ships python, not curl/wget."""
    code = (
        "import sys, urllib.request\n"
        f"r = urllib.request.urlopen('http://{ip}:{port}/', timeout=5)\n"
        "print('BODY', r.read().decode('utf-8', 'replace'))\n"
    )
    return SandboxExecSpec(command="python", args=["-c", code], timeout_seconds=30)


@pytest.fixture
def egress_env() -> Iterator[EgressEnv]:
    """Per-test restricted network with one pinned target listener."""
    suffix = uuid.uuid4().hex[:8]
    target_name = f"quarry-it-btarget-{suffix}"

    for _ in range(20):
        octet = 1 + uuid.uuid4().int % 254
        base = f"172.30.{octet}."
        ips = {"target-host": f"{base}5"}
        policy = _policy(ips)
        network = egress_network_name(policy)
        assert network is not None
        created = _run(
            [
                "docker",
                "network",
                "create",
                "--internal",
                "--subnet",
                f"172.30.{octet}.0/24",
                network,
            ]
        )
        if created.returncode == 0:
            break
    else:
        pytest.skip("could not allocate an isolated Docker subnet")

    _run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            target_name,
            "--network",
            network,
            "--ip",
            ips["target-host"],
            LISTENER_IMAGE,
            "sh",
            "-c",
            _listener_cmd("TARGET", 8080),
        ]
    )
    time.sleep(2)
    try:
        yield policy, ips
    finally:
        _run(["docker", "rm", "-f", target_name])
        _run(["docker", "network", "rm", network])


class TestBrowserWorkerContainment:
    """t_fbe652c1 acceptance: egress-restricted + memory-capped browser container."""

    def test_browser_container_reaches_pinned_target(
        self, tmp_path: Path, egress_env: EgressEnv
    ) -> None:
        """Sanity: the pinned target IS reachable on the restricted network."""
        image = _browser_image()
        assert image is not None
        policy, ips = egress_env
        sandbox = ContainerSandbox(image=image, memory_limit=MEMORY_LIMIT)

        result = sandbox.run(
            _fetch_spec(ips["target-host"], 8080),
            work_dir=tmp_path,
            resolved_env={},
            egress_policy=policy,
        )
        assert "BODY TARGET" in result.stdout, (result.stdout, result.stderr)

    def test_browser_container_cannot_reach_unlisted_host(
        self, tmp_path: Path, egress_env: EgressEnv
    ) -> None:
        """A host outside the policy is unreachable from the browser container."""
        image = _browser_image()
        assert image is not None
        policy, _ips = egress_env
        sandbox = ContainerSandbox(image=image, memory_limit=MEMORY_LIMIT)

        result = sandbox.run(
            _fetch_spec("1.1.1.1", 80),
            work_dir=tmp_path,
            resolved_env={},
            egress_policy=policy,
        )
        assert "BODY" not in result.stdout, result.stdout
        assert result.exit_code != 0, (result.stdout, result.stderr)

    def test_browser_container_memory_is_capped(
        self, tmp_path: Path, egress_env: EgressEnv
    ) -> None:
        """The container's kernel-enforced memory limit equals the configured cap."""
        image = _browser_image()
        assert image is not None
        policy, _ips = egress_env
        sandbox = ContainerSandbox(image=image, memory_limit=MEMORY_LIMIT)

        spec = SandboxExecSpec(
            command="python",
            args=["-c", "print('MAX', open('/sys/fs/cgroup/memory.max').read().strip())"],
            timeout_seconds=30,
        )
        result = sandbox.run(
            spec,
            work_dir=tmp_path,
            resolved_env={},
            egress_policy=policy,
        )
        assert f"MAX {MEMORY_LIMIT_BYTES}" in result.stdout, (result.stdout, result.stderr)
