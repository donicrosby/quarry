"""Integration: the authZ matrix stage (W14).

Contracts tested:

1. ``build_authz_matrix_endpoints`` (workflow-side pre-resolution) drops
   endpoints outside the top-level authorization — including any matching a
   top-level ``do_not_test`` pattern — and dedups the rest.
2. The ``authz-matrix`` activity is discovered by the registry, runs under a real
   Temporal worker, and produces the persisted matrix artifact.

Full ``RunScanWorkflow`` driving is intentionally not attempted here: per this
repo's convention (see ``test_lifecycle_hooks_e2e.py``) workflow dispatch logic
is verified through pure helpers plus the activity running for real, not through
a full agentic scan (no e2e fixture wires a hunt/validate MockModelClient).
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from quarry.schemas import TargetAuthorization, TargetEndpoint
from quarry_activities.authz_matrix import (
    AuthzMatrixActivityInput,
    AuthzMatrixEndpoint,
    AuthzMatrixPersona,
    authz_matrix_activity,
)
from quarry_workflows.run_scan import build_authz_matrix_endpoints
from tests.authz_matrix_probe_workflow import AuthzMatrixProbeWorkflow

_NOW = datetime(2026, 7, 31, tzinfo=UTC)


class _MatrixHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        payload = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@pytest.fixture
def matrix_server() -> Iterator[int]:
    server = HTTPServer(("127.0.0.1", 0), _MatrixHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _authz(**overrides: Any) -> TargetAuthorization:
    base: dict[str, Any] = {
        "id": "auth-1",
        "target_id": "tgt-1",
        "workspace_id": "local",
        "authorized_by": "secops@example.com",
        "allowed_hosts": ["127.0.0.1"],
        "allowed_repo_paths": ["/"],
        "created_at": _NOW,
    }
    base.update(overrides)
    return TargetAuthorization.model_validate(base)


class TestBuildAuthzMatrixEndpoints:
    def test_do_not_test_path_is_never_probed(self) -> None:
        authz = _authz(do_not_test=["/admin/*"])
        endpoints = build_authz_matrix_endpoints(
            [{"method": "GET", "path": "/admin/users"}, {"method": "GET", "path": "/public"}],
            authz,
            host="127.0.0.1",
        )
        assert [e.path for e in endpoints] == ["/public"]

    def test_out_of_scope_host_is_dropped(self) -> None:
        authz = _authz(allowed_hosts=["other.example"])
        endpoints = build_authz_matrix_endpoints(
            [{"method": "GET", "path": "/public"}], authz, host="127.0.0.1"
        )
        assert endpoints == []

    def test_duplicates_collapsed_and_method_preserved(self) -> None:
        authz = _authz()
        endpoints = build_authz_matrix_endpoints(
            [
                {"method": "GET", "path": "/a"},
                {"method": "GET", "path": "/a"},
                {"method": "POST", "path": "/a"},
            ],
            authz,
            host="127.0.0.1",
        )
        assert [(e.method, e.path) for e in endpoints] == [("GET", "/a"), ("POST", "/a")]

    def test_malformed_entries_ignored(self) -> None:
        authz = _authz()
        endpoints = build_authz_matrix_endpoints(
            ["not-a-dict", {"path": ""}, {"method": "GET", "path": "/ok"}],
            authz,
            host="127.0.0.1",
        )
        assert [e.path for e in endpoints] == ["/ok"]


class TestAuthzMatrixActivityUnderTemporal:
    async def test_activity_runs_and_produces_artifact(
        self,
        temporal_env: WorkflowEnvironment,
        matrix_server: int,
        tmp_path: Path,
    ) -> None:
        client = temporal_env.client
        endpoint = TargetEndpoint(host="127.0.0.1", port=matrix_server)
        activity_input = AuthzMatrixActivityInput(
            scan_id="scan-matrix-temporal",
            target_endpoint_json=endpoint.model_dump_json(),
            allowed_hosts=("127.0.0.1",),
            artifact_store_path=str(tmp_path),
            endpoints=[AuthzMatrixEndpoint(method="GET", path="/public")],
            personas=[
                AuthzMatrixPersona(
                    name="anon",
                    profile_ref=None,
                    privilege_level="unauthenticated",
                )
            ],
            min_request_interval_seconds=0.0,
        )
        async with Worker(
            client,
            task_queue="authz-matrix-test",
            workflows=[AuthzMatrixProbeWorkflow],
            activities=[authz_matrix_activity],
        ):
            result = await client.execute_workflow(
                AuthzMatrixProbeWorkflow.run,
                activity_input,
                id="authz-matrix-wf",
                task_queue="authz-matrix-test",
            )
        assert result.rows[0].cells[0].status_code == 200
        assert result.artifact_ref is not None
        stored = tmp_path / "scan-matrix-temporal" / "authz_matrix" / "matrix.json"
        assert stored.is_file()
