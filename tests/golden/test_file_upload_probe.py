"""Golden: file-upload probe against ``vulnerable-fastapi`` end to end.

Boots the example target through the same launcher the CLI uses, forges a
multipart/form-data POST through the ``http-request`` activity (the sole egress
point), and asserts:

- the upload sink accepted the file (response carries the stored path and the
  unvalidated ``.php`` extension), and
- the stored request artifact records a real ``multipart/form-data`` body, so
  the probe genuinely travelled as a multipart upload rather than a raw body.

The fixture's ``/upload`` handler reads ``filename``/``content`` as query
parameters, so the path also carries them — the multipart parts exercise the
forging path, and the sink's acceptance proves the post-upload result fetch.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from quarry.schemas import HttpRequestSpec, MultipartFieldSpec, TargetEndpoint
from quarry_activities.dynamic_http import http_request_activity
from quarry_activities.inputs import HttpRequestActivityInput
from quarry_activities.target import start_local_target, terminate_local_target

REPO_ROOT = Path("examples/vulnerable-fastapi")
_SCAN_ID = "scan-golden-file-upload"


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_file_upload_multipart_post_round_trip(tmp_path: Path) -> None:
    port = _free_local_port()
    process = start_local_target(
        REPO_ROOT.resolve(), host="127.0.0.1", port=port, timeout_seconds=60.0
    )
    try:
        filename = f"quarry-probe-{port}.php"
        spec = HttpRequestSpec(
            method="POST",
            path=f"/upload?filename={filename}&content=%3C%3Fphp%20echo%201%3B%20%3F%3E",
            multipart_fields=[
                MultipartFieldSpec(
                    name="file",
                    value="<?php echo 1; ?>",
                    filename=filename,
                    content_type="application/x-php",
                )
            ],
        )
        inp = HttpRequestActivityInput(
            spec_json=spec.model_dump_json(),
            target_endpoint_json=TargetEndpoint(host="127.0.0.1", port=port).model_dump_json(),
            allowed_hosts=("127.0.0.1",),
            artifact_store_path=str(tmp_path),
            scan_id=_SCAN_ID,
            candidate_finding_id="gt-file-upload-upload",
        )
        capture = await http_request_activity(inp)
    finally:
        terminate_local_target(process)

    assert capture.status_code == 200

    body_key = capture.body_artifact_key or ""
    body = json.loads((tmp_path / _SCAN_ID / body_key).read_text(encoding="utf-8"))["body"]
    result = json.loads(body)
    assert result["extension"] == ".php", "upload sink must report the unvalidated extension"
    assert result["stored"].endswith(filename)

    request_artifacts = sorted((tmp_path / _SCAN_ID / "http" / "requests").glob("*.json"))
    assert len(request_artifacts) == 1
    artifact = json.loads(request_artifacts[0].read_text(encoding="utf-8"))
    assert artifact["method"] == "POST"
    content_type = next(
        value for key, value in artifact["headers"].items() if key.lower() == "content-type"
    )
    assert content_type.startswith("multipart/form-data; boundary=")
