"""Integration: RedisArtifactStore against a real Redis container (task 7.4).

Gated like the other live-docker suites: skips unless the docker CLI reaches a
daemon and the ``redis:7-alpine`` image is present locally. The container is
reached by its bridge IP (the sandbox cannot see host-published ports).
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from collections.abc import Iterator

import pytest

from quarry.schemas import ArtifactKind, ArtifactRef
from quarry_artifacts.redis_store import RedisArtifactStore
from quarry_artifacts.store import build_artifact_store

REDIS_IMAGE = "redis:7-alpine"


def _skip_reason() -> str | None:
    if shutil.which("docker") is None:
        return "docker CLI not found on PATH"
    probe = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if probe.returncode != 0:
        return "docker daemon not reachable"
    images = subprocess.run(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if REDIS_IMAGE not in images.stdout:
        return f"{REDIS_IMAGE} not present locally"
    return None


_SKIP = _skip_reason()
pytestmark = pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")


def _wait_port(host: str, port: int, timeout: float = 40.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(2.0)
            try:
                sock.connect((host, port))
                return
            except OSError:
                time.sleep(0.5)
    msg = f"container port {host}:{port} never became reachable"
    raise TimeoutError(msg)


@pytest.fixture(scope="module")
def redis_url() -> Iterator[str]:
    cid = subprocess.run(
        ["docker", "run", "-d", "--rm", REDIS_IMAGE],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    try:
        ip = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                cid,
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        _wait_port(ip, 6379)
        yield f"redis://{ip}:6379/0"
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, text=True)


def test_put_get_round_trip(redis_url: str) -> None:
    store = RedisArtifactStore(redis_url)
    try:
        ref = store.put_bytes(
            "scan-it/artifact.bin",
            b"\x00\x01binary-payload",
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="application/octet-stream",
        )
        assert ref.uri.startswith("redis://")
        assert store.get_bytes(ref) == b"\x00\x01binary-payload"
    finally:
        store.close()


def test_oversized_rejected(redis_url: str) -> None:
    store = RedisArtifactStore(redis_url, max_artifact_bytes=4)
    try:
        with pytest.raises(ValueError, match="exceeding"):
            store.put_bytes("k", b"12345", kind=ArtifactKind.TOOL_STDOUT, content_type="text/plain")
    finally:
        store.close()


def test_factory_dispatch_against_live_redis(
    redis_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """QUARRY_ARTIFACT_BACKEND=redis serves a scan artifact end to end."""
    monkeypatch.setenv("QUARRY_ARTIFACT_BACKEND", "redis")
    monkeypatch.setenv("QUARRY_REDIS_URL", redis_url)
    store = build_artifact_store(root="")
    try:
        assert isinstance(store, RedisArtifactStore)
        ref: ArtifactRef = store.put_json(
            "scan-it/report.json",
            _Json({"ok": True}),
            kind=ArtifactKind.REPORT,
        )
        assert b'"ok": true' in store.get_bytes(ref)
    finally:
        store.close()


class _Json:
    def __init__(self, payload: dict[str, bool]) -> None:
        self._payload = payload

    def model_dump_json(self, *, indent: int | None = None) -> str:
        import json

        return json.dumps(self._payload)
