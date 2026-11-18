"""Golden: file-upload testing chains against ``vulnerable-fastapi``.

Boots the example target through the launcher the CLI uses and drives the
``http-request`` activity (the sole egress point) to prove the unrestricted
upload sink end to end:

- the upload→fetch-back chain: a real ``multipart/form-data`` POST stores the
  probe, then a second request reads the stored bytes back (write + read proven);
- the four upload test cases — forbidden extension (PHP shell), path traversal
  in the filename, content-type bypass, and an oversized body with no server-side
  cap.

Every probe carries an inert marker only; nothing executable is uploaded.
"""

from __future__ import annotations

import json
import socket
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from quarry.schemas import HttpRequestSpec, MultipartFieldSpec, TargetEndpoint
from quarry_activities.dynamic_http import http_request_activity
from quarry_activities.inputs import HttpRequestActivityInput
from quarry_activities.target import start_local_target, terminate_local_target

REPO_ROOT = Path("examples/vulnerable-fastapi")
_SCAN_ID = "scan-golden-file-upload-chains"
_MARKER = "QRYMARKER-W13"
_UPLOAD_DIR = Path(tempfile.gettempdir()) / "quarry-vulnerable-uploads"


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def _launched_target() -> Generator[int]:
    port = _free_local_port()
    process = start_local_target(
        REPO_ROOT.resolve(), host="127.0.0.1", port=port, timeout_seconds=60.0
    )
    try:
        yield port
    finally:
        terminate_local_target(process)


def _activity_input(
    spec: HttpRequestSpec, *, port: int, tmp_path: Path, finding: str
) -> HttpRequestActivityInput:
    return HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=TargetEndpoint(host="127.0.0.1", port=port).model_dump_json(),
        allowed_hosts=("127.0.0.1",),
        artifact_store_path=str(tmp_path),
        scan_id=_SCAN_ID,
        candidate_finding_id=finding,
    )


def _body(capture: object, tmp_path: Path) -> str:
    key = getattr(capture, "body_artifact_key", None) or ""
    return json.loads((tmp_path / _SCAN_ID / key).read_text(encoding="utf-8"))["body"]


def _upload_spec(filename: str, value: str, content_type: str) -> HttpRequestSpec:
    return HttpRequestSpec(
        method="POST",
        path="/upload",
        multipart_fields=[
            MultipartFieldSpec(
                name="file", value=value, filename=filename, content_type=content_type
            )
        ],
    )


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_upload_then_fetch_back_reads_marker(tmp_path: Path) -> None:
    with _launched_target() as port:
        name = f"w13-roundtrip-{port}.txt"
        upload = _upload_spec(name, _MARKER, "text/plain")
        up = await http_request_activity(
            _activity_input(upload, port=port, tmp_path=tmp_path, finding="w13-upload")
        )
        assert up.status_code == 200
        stored = json.loads(_body(up, tmp_path))
        assert stored["extension"] == ".txt"

        fetch = HttpRequestSpec(method="GET", path=f"/uploads/{name}")
        got = await http_request_activity(
            _activity_input(fetch, port=port, tmp_path=tmp_path, finding="w13-fetch")
        )

    assert got.status_code == 200
    served = json.loads(_body(got, tmp_path))
    assert served["content"] == _MARKER, "the stored file is served back verbatim"


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_php_shell_extension_is_accepted(tmp_path: Path) -> None:
    with _launched_target() as port:
        name = f"w13-shell-{port}.php"
        spec = _upload_spec(name, "<?php echo 1; ?>", "application/x-php")
        capture = await http_request_activity(
            _activity_input(spec, port=port, tmp_path=tmp_path, finding="w13-shell")
        )

    assert capture.status_code == 200
    result = json.loads(_body(capture, tmp_path))
    assert result["extension"] == ".php", "no server-side extension allow-list"
    assert result["stored"].endswith(name)


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_path_traversal_filename_escapes_upload_dir(tmp_path: Path) -> None:
    with _launched_target() as port:
        # upload_dir is <tmp>/quarry-vulnerable-uploads; "../<name>" resolves one
        # level up — outside the upload dir — and the temp root exists.
        traversal = f"../w13-traversal-{port}.txt"
        spec = _upload_spec(traversal, _MARKER, "text/plain")
        capture = await http_request_activity(
            _activity_input(spec, port=port, tmp_path=tmp_path, finding="w13-traversal")
        )

    assert capture.status_code == 200
    result = json.loads(_body(capture, tmp_path))
    stored = Path(result["stored"]).resolve()
    assert stored.is_file()
    assert stored.read_text(encoding="utf-8") == _MARKER
    assert _UPLOAD_DIR.resolve() not in stored.parents, "the write escaped the upload dir"


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_content_type_mismatch_is_accepted(tmp_path: Path) -> None:
    with _launched_target() as port:
        name = f"w13-ct-{port}.php"
        # A dangerous extension declared as a benign content-type.
        spec = _upload_spec(name, _MARKER, "text/plain")
        capture = await http_request_activity(
            _activity_input(spec, port=port, tmp_path=tmp_path, finding="w13-ct")
        )

    assert capture.status_code == 200
    result = json.loads(_body(capture, tmp_path))
    assert result["extension"] == ".php", "the declared content-type is not validated"


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_oversized_upload_has_no_server_side_cap(tmp_path: Path) -> None:
    with _launched_target() as port:
        name = f"w13-oversized-{port}.bin"
        payload = "A" * (256 * 1024)  # 256 KiB — far beyond any legitimate probe
        spec = _upload_spec(name, payload, "application/octet-stream")
        capture = await http_request_activity(
            _activity_input(spec, port=port, tmp_path=tmp_path, finding="w13-oversized")
        )

    assert capture.status_code == 200
    result = json.loads(_body(capture, tmp_path))
    stored = Path(result["stored"])
    assert stored.is_file()
    assert stored.stat().st_size == len(payload), "no server-side size cap was enforced"
