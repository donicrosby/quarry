"""Integration: S3ArtifactStore against MinIO (task 7.5).

Gated like the other live-docker suites: skips unless the docker CLI reaches a
daemon and the ``minio/minio:latest`` image is present locally. The container is
reached by its bridge IP. Credentials/endpoint flow through the standard AWS SDK
env vars (``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` / ``AWS_ENDPOINT_URL``).
"""

from __future__ import annotations

import importlib
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest

from quarry.schemas import ArtifactKind, ArtifactRef
from quarry_artifacts.s3_store import S3ArtifactStore
from quarry_artifacts.store import build_artifact_store

MINIO_IMAGE = "minio/minio:latest"
MINIO_USER = "minioadmin"
MINIO_PASSWORD = "minioadmin"
BUCKET = "quarry-test"


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
    if MINIO_IMAGE not in images.stdout:
        return f"{MINIO_IMAGE} not present locally"
    return None


_SKIP = _skip_reason()
pytestmark = pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")


def _container_ip(cid: str) -> str:
    return subprocess.run(
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


def _wait_health(url: str, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310 - fixed local URL
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    msg = f"MinIO health endpoint {url} never became ready"
    raise TimeoutError(msg)


@pytest.fixture(scope="module")
def minio_endpoint() -> Iterator[str]:
    cid = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "-e",
            f"MINIO_ROOT_USER={MINIO_USER}",
            "-e",
            f"MINIO_ROOT_PASSWORD={MINIO_PASSWORD}",
            MINIO_IMAGE,
            "server",
            "/data",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    try:
        ip = _container_ip(cid)
        endpoint = f"http://{ip}:9000"
        _wait_health(f"{endpoint}/minio/health/live")
        boto3: Any = importlib.import_module("boto3")
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=MINIO_USER,
            aws_secret_access_key=MINIO_PASSWORD,
            region_name="us-east-1",
        )
        client.create_bucket(Bucket=BUCKET)
        yield endpoint
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, text=True)


def _aws_env(monkeypatch: pytest.MonkeyPatch, endpoint: str) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", MINIO_USER)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", MINIO_PASSWORD)
    monkeypatch.setenv("AWS_ENDPOINT_URL", endpoint)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    # Ensure a real (non-MinIO) endpoint is not picked up from the ambient env.
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def test_put_get_round_trip(minio_endpoint: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws_env(monkeypatch, minio_endpoint)
    store = S3ArtifactStore(BUCKET)
    try:
        ref = store.put_bytes(
            "scan-it/binary",
            b"\x7fELF-payload",
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="application/octet-stream",
        )
        assert ref.uri == f"s3://{BUCKET}/scan-it/binary"
        assert store.get_bytes(ref) == b"\x7fELF-payload"
    finally:
        store.close()


def test_factory_dispatch_scan_artifact(
    minio_endpoint: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """QUARRY_ARTIFACT_BACKEND=s3 serves a scan artifact end to end (acceptance)."""
    _aws_env(monkeypatch, minio_endpoint)
    monkeypatch.setenv("QUARRY_ARTIFACT_BACKEND", "s3")
    monkeypatch.setenv("QUARRY_S3_BUCKET", BUCKET)
    store = build_artifact_store(root="")
    try:
        assert isinstance(store, S3ArtifactStore)
        ref: ArtifactRef = store.put_json(
            "scan-it/report.json", _Json({"ok": True}), kind=ArtifactKind.REPORT
        )
        assert b'"ok": true' in store.get_bytes(ref)
    finally:
        store.close()


def test_credential_failure_names_bucket(minio_endpoint: str) -> None:
    # boto3 caches the default session's resolved credentials, so drive this case
    # with a client built from explicitly wrong keys rather than env mutation.
    boto3: Any = importlib.import_module("boto3")
    bad_client = boto3.client(
        "s3",
        endpoint_url=minio_endpoint,
        aws_access_key_id="wrong-key",
        aws_secret_access_key=MINIO_PASSWORD,
        region_name="us-east-1",
    )
    store = S3ArtifactStore(BUCKET, client=bad_client)
    try:
        with pytest.raises(ValueError, match=BUCKET):
            store.put_bytes("k", b"x", kind=ArtifactKind.TOOL_STDOUT, content_type="text/plain")
    finally:
        store.close()


class _Json:
    def __init__(self, payload: dict[str, bool]) -> None:
        self._payload = payload

    def model_dump_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self._payload)
