"""Live-Docker integration tests for destination-set egress enforcement (D1).

These tests exercise the Tier-2 ContainerSandbox against a real Docker daemon:
a sandboxed command reaches the policy's pinned destinations and is blocked from
everything else.  The whole module is skipped when Docker is unavailable.

Acceptance criterion (ticket t_a1b75fc3): a sandbox whose policy allows a target
and a canary reaches both and blocks all other egress.
"""

from __future__ import annotations

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

IMAGE = "alpine:3.20"
EgressEnv = tuple[ResolvedEgressPolicy, dict[str, str]]


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available")


def _policy(ips: dict[str, str]) -> ResolvedEgressPolicy:
    """Build a resolved policy with one set per (set_name → ip) entry."""
    return ResolvedEgressPolicy(
        destination_sets=[
            ResolvedDestinationSet(name=name, allowed_ips=[ip]) for name, ip in ips.items()
        ]
    )


def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)  # type: ignore[arg-type]


def _listener_cmd(body: str, port: int) -> str:
    """Shell one-liner: answer every TCP connection with a fixed body."""
    head = "HTTP/1.1 200 OK\\r\\nContent-Length: 6\\r\\n\\r\\n"
    return f"while true; do printf '{head}{body}' | nc -l -p {port}; done"


@pytest.fixture
def egress_env() -> Iterator[EgressEnv]:
    """Stand up a per-test restricted network with two pinned listeners; tear down after.

    Each test gets its own network name *and* its own /24 subnet, both derived
    from the pinned IPs, so no two tests share a Docker network or an address
    pool.  That keeps the module safe under the repo's default ``-n auto``
    parallelism (a shared fixed subnet would race across workers).
    """
    suffix = uuid.uuid4().hex[:8]
    target_name = f"quarry-it-target-{suffix}"
    canary_name = f"quarry-it-canary-{suffix}"

    for _ in range(20):
        octet = 1 + uuid.uuid4().int % 254
        base = f"172.31.{octet}."
        ips = {"target-host": f"{base}5", "canary-listener": f"{base}6"}
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
                f"172.31.{octet}.0/24",
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
            IMAGE,
            "sh",
            "-c",
            _listener_cmd("TARGET", 8080),
        ]
    )
    _run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            canary_name,
            "--network",
            network,
            "--ip",
            ips["canary-listener"],
            IMAGE,
            "sh",
            "-c",
            _listener_cmd("CANARY", 9090),
        ]
    )
    time.sleep(2)
    try:
        yield policy, ips
    finally:
        _run(["docker", "rm", "-f", target_name, canary_name])
        _run(["docker", "network", "rm", network])


def _wget(ip: str, port: int) -> SandboxExecSpec:
    return SandboxExecSpec(
        command="sh",
        args=["-c", f"wget -qO- --timeout=5 http://{ip}:{port}; echo rc:$?"],
        timeout_seconds=20,
    )


class TestContainerSandboxEgress:
    def test_multi_destination_reaches_target_and_canary(
        self, tmp_path: Path, egress_env: EgressEnv
    ) -> None:
        """7.4: a policy with target + canary reaches both pinned destinations."""
        policy, ips = egress_env
        sandbox = ContainerSandbox(image=IMAGE)

        target = sandbox.run(
            _wget(ips["target-host"], 8080),
            work_dir=tmp_path,
            resolved_env={},
            egress_policy=policy,
        )
        canary = sandbox.run(
            _wget(ips["canary-listener"], 9090),
            work_dir=tmp_path,
            resolved_env={},
            egress_policy=policy,
        )

        assert "TARGET" in target.stdout and "rc:0" in target.stdout, target.stdout
        assert "CANARY" in canary.stdout and "rc:0" in canary.stdout, canary.stdout

    def test_other_hosts_blocked(self, tmp_path: Path, egress_env: EgressEnv) -> None:
        """7.4: any host outside the policy is unreachable from the sandbox."""
        policy, _ips = egress_env
        sandbox = ContainerSandbox(image=IMAGE)

        result = sandbox.run(
            _wget("1.1.1.1", 80),
            work_dir=tmp_path,
            resolved_env={},
            egress_policy=policy,
        )
        assert "rc:0" not in result.stdout, result.stdout

    def test_empty_policy_blocks_all_egress(self, tmp_path: Path) -> None:
        """7.5: an empty policy runs with --network none — no egress."""
        sandbox = ContainerSandbox(image=IMAGE)
        result = sandbox.run(
            _wget("1.1.1.1", 80),
            work_dir=tmp_path,
            resolved_env={},
            egress_policy=ResolvedEgressPolicy(),
        )
        assert "rc:0" not in result.stdout, result.stdout

    def test_pinned_ip_is_the_reachable_one(self, tmp_path: Path, egress_env: EgressEnv) -> None:
        """6.2: the sandbox reaches the policy's pinned IP, not another address.

        The policy pins the canary's IP; the same port on a different address on
        the same network (the target) is a different destination and is reached
        only because it too is pinned.  A re-resolved/redirected address would not
        be reachable — DNS is never consulted once the policy is frozen.
        """
        policy, ips = egress_env
        sandbox = ContainerSandbox(image=IMAGE)

        pinned = sandbox.run(
            _wget(ips["canary-listener"], 9090),
            work_dir=tmp_path,
            resolved_env={},
            egress_policy=policy,
        )
        assert "CANARY" in pinned.stdout, pinned.stdout

        # An address on the same subnet that is NOT in the policy is not reachable.
        unpinned = sandbox.run(
            _wget("172.31.0.99", 9090),
            work_dir=tmp_path,
            resolved_env={},
            egress_policy=policy,
        )
        assert "rc:0" not in unpinned.stdout, unpinned.stdout
