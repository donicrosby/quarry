"""W14 authZ matrix activity + violation-detection + emission tests.

Groups 3-5, 7:

- the ``authz-matrix`` activity probes every endpoint as every persona and
  records the real status code and body hash from a stub HTTP server, without
  aborting on a 5xx;
- ``detect_authz_violations`` fires only on *declared* ground truth
  (``expected_denied_paths``), never on body-hash differences, and treats
  error/5xx cells as inconclusive;
- violations emit ``CandidateFinding``s with the pinned ``vuln_class`` mapping
  and matrix-artifact/persona provenance, plus gapfill-shaped hunt tasks.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    RedactionStatus,
    TargetEndpoint,
    VulnerabilityClass,
)
from quarry_activities.authz_matrix import (
    AuthzMatrixActivityInput,
    AuthzMatrixCell,
    AuthzMatrixEndpoint,
    AuthzMatrixPersona,
    AuthzMatrixResult,
    AuthzMatrixRow,
    AuthzViolation,
    authz_matrix_activity,
    build_authz_candidates,
    build_authz_hunt_tasks,
    detect_authz_violations,
)

_NOW = datetime(2026, 7, 31, tzinfo=UTC)
_PUBLIC_BODY = "hello-public"


class _MatrixHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        if self.path == "/admin/users":
            self._respond(403, "forbidden")
        elif self.path == "/public":
            self._respond(200, _PUBLIC_BODY)
        elif self.path == "/boom":
            self._respond(500, "server error")
        else:
            self._respond(404, "not found")

    def _respond(self, status: int, body: str) -> None:
        payload = body.encode()
        self.send_response(status)
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _persona(name: str, privilege: str, denied: list[str] | None = None) -> AuthzMatrixPersona:
    return AuthzMatrixPersona(
        name=name,
        profile_ref=None if privilege == "unauthenticated" else f"{name}-profile",
        privilege_level=privilege,  # type: ignore[arg-type]
        expected_denied_paths=denied or [],
    )


def _endpoint(path: str, method: str = "GET") -> AuthzMatrixEndpoint:
    return AuthzMatrixEndpoint(method=method, path=path)


def _cell(persona: str, status: int | None, body_hash: str | None = None) -> AuthzMatrixCell:
    return AuthzMatrixCell(persona=persona, status_code=status, body_hash=body_hash)


def _result(
    rows: list[AuthzMatrixRow],
    personas: list[AuthzMatrixPersona],
    artifact_ref: ArtifactRef | None = None,
) -> AuthzMatrixResult:
    return AuthzMatrixResult(
        scan_id="scan-matrix",
        personas=personas,
        rows=rows,
        artifact_ref=artifact_ref,
    )


def _artifact_ref() -> ArtifactRef:
    return ArtifactRef(
        id="art-matrix",
        uri="file:///tmp/authz_matrix/matrix.json",
        kind=ArtifactKind.AUTHZ_MATRIX,
        content_type="application/json",
        sha256="0" * 64,
        size_bytes=42,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=_NOW,
    )


def _input(
    port: int,
    endpoints: list[AuthzMatrixEndpoint],
    personas: list[AuthzMatrixPersona],
    artifact_root: Path,
) -> AuthzMatrixActivityInput:
    endpoint = TargetEndpoint(host="127.0.0.1", port=port)
    return AuthzMatrixActivityInput(
        scan_id="scan-matrix",
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=("127.0.0.1",),
        artifact_store_path=str(artifact_root),
        endpoints=endpoints,
        personas=personas,
        min_request_interval_seconds=0.0,
    )


# ---------------------------------------------------------------------------
# Group 3: the matrix activity
# ---------------------------------------------------------------------------


class TestAuthzMatrixActivity:
    async def test_matrix_dimensions_and_status_codes(
        self, matrix_server: int, tmp_path: Path
    ) -> None:
        personas = [_persona("anon", "unauthenticated"), _persona("user", "user")]
        endpoints = [_endpoint("/public"), _endpoint("/admin/users")]
        result = await authz_matrix_activity(_input(matrix_server, endpoints, personas, tmp_path))

        assert len(result.rows) == 2
        assert all(len(row.cells) == 2 for row in result.rows)
        # Rows are sorted by path (deterministic ordering).
        assert [row.endpoint_path for row in result.rows] == ["/admin/users", "/public"]
        by_path = {row.endpoint_path: row for row in result.rows}
        assert by_path["/admin/users"].cells[0].status_code == 403
        assert by_path["/public"].cells[0].status_code == 200

    async def test_cell_records_body_hash(self, matrix_server: int, tmp_path: Path) -> None:
        personas = [_persona("anon", "unauthenticated")]
        result = await authz_matrix_activity(
            _input(matrix_server, [_endpoint("/public")], personas, tmp_path)
        )
        cell = result.rows[0].cells[0]
        assert cell.body_hash == sha256(_PUBLIC_BODY.encode()).hexdigest()

    async def test_5xx_does_not_abort_matrix(self, matrix_server: int, tmp_path: Path) -> None:
        personas = [_persona("anon", "unauthenticated")]
        endpoints = [_endpoint("/boom"), _endpoint("/public")]
        result = await authz_matrix_activity(_input(matrix_server, endpoints, personas, tmp_path))
        by_path = {row.endpoint_path: row for row in result.rows}
        assert by_path["/boom"].cells[0].status_code == 500
        # The remaining endpoint is still recorded after the 5xx.
        assert by_path["/public"].cells[0].status_code == 200

    async def test_artifact_persisted(self, matrix_server: int, tmp_path: Path) -> None:
        personas = [_persona("anon", "unauthenticated")]
        result = await authz_matrix_activity(
            _input(matrix_server, [_endpoint("/public")], personas, tmp_path)
        )
        assert result.artifact_ref is not None
        assert result.artifact_ref.kind == ArtifactKind.AUTHZ_MATRIX
        stored = tmp_path / "scan-matrix" / "authz_matrix" / "matrix.json"
        assert stored.is_file()

    async def test_transport_error_recorded_and_matrix_continues(self, tmp_path: Path) -> None:
        # No server on this port → connection refused; the cell records the error
        # and the matrix still returns rows.
        personas = [_persona("anon", "unauthenticated")]
        result = await authz_matrix_activity(_input(9, [_endpoint("/x")], personas, tmp_path))
        assert result.rows[0].cells[0].error is not None
        assert result.rows[0].cells[0].status_code is None


# ---------------------------------------------------------------------------
# Group 4: declared-ground-truth violation detection
# ---------------------------------------------------------------------------


class TestDetectAuthzViolations:
    def test_unauth_200_on_declared_denied_path_is_unauth_access(self) -> None:
        personas = [_persona("anon", "unauthenticated", denied=["/admin/*"])]
        matrix = _result(
            [
                AuthzMatrixRow(
                    endpoint_path="/admin/users", endpoint_method="GET", cells=[_cell("anon", 200)]
                )
            ],
            personas,
        )
        violations = detect_authz_violations(matrix)
        assert [v.kind for v in violations] == ["unauth_access"]

    def test_user_200_on_declared_denied_path_is_privilege_escalation(self) -> None:
        personas = [_persona("user", "user", denied=["/admin/*"])]
        matrix = _result(
            [
                AuthzMatrixRow(
                    endpoint_path="/admin/users", endpoint_method="GET", cells=[_cell("user", 200)]
                )
            ],
            personas,
        )
        violations = detect_authz_violations(matrix)
        assert [v.kind for v in violations] == ["privilege_escalation"]

    def test_unauth_200_on_undeclared_path_raises_nothing(self) -> None:
        personas = [_persona("anon", "unauthenticated", denied=[])]
        matrix = _result(
            [
                AuthzMatrixRow(
                    endpoint_path="/public", endpoint_method="GET", cells=[_cell("anon", 200)]
                )
            ],
            personas,
        )
        assert detect_authz_violations(matrix) == []

    def test_same_privilege_different_status_classes_is_inconsistent(self) -> None:
        personas = [_persona("user-a", "user"), _persona("user-b", "user")]
        matrix = _result(
            [
                AuthzMatrixRow(
                    endpoint_path="/x",
                    endpoint_method="GET",
                    cells=[_cell("user-a", 200), _cell("user-b", 403)],
                )
            ],
            personas,
        )
        assert [v.kind for v in detect_authz_violations(matrix)] == ["inconsistent_authz"]

    def test_same_privilege_same_status_different_body_hashes_raise_nothing(self) -> None:
        personas = [_persona("user-a", "user"), _persona("user-b", "user")]
        matrix = _result(
            [
                AuthzMatrixRow(
                    endpoint_path="/x",
                    endpoint_method="GET",
                    cells=[_cell("user-a", 200, "a" * 64), _cell("user-b", 200, "b" * 64)],
                )
            ],
            personas,
        )
        assert detect_authz_violations(matrix) == []

    def test_error_and_5xx_cells_are_inconclusive(self) -> None:
        personas = [_persona("anon", "unauthenticated", denied=["/admin/*"])]
        rows = [
            AuthzMatrixRow(
                endpoint_path="/admin/a", endpoint_method="GET", cells=[_cell("anon", 500)]
            ),
            AuthzMatrixRow(
                endpoint_path="/admin/b",
                endpoint_method="GET",
                cells=[AuthzMatrixCell(persona="anon", error="ConnectError")],
            ),
        ]
        assert detect_authz_violations(_result(rows, personas)) == []

    def test_inert_preconditions_raise_nothing(self) -> None:
        # No expected_denied_paths declared anywhere → the rule is inert.
        personas = [_persona("user", "user")]
        matrix = _result(
            [AuthzMatrixRow(endpoint_path="/x", endpoint_method="GET", cells=[_cell("user", 200)])],
            personas,
        )
        assert detect_authz_violations(matrix) == []


# ---------------------------------------------------------------------------
# Group 5: candidate-finding + hunt-task emission
# ---------------------------------------------------------------------------


class TestAuthzEmission:
    def _violations(self) -> list[AuthzViolation]:
        return [
            AuthzViolation(
                kind="unauth_access",
                endpoint_path="/admin/users",
                endpoint_method="GET",
                persona="anon",
                privilege_level="unauthenticated",
                status_code=200,
            ),
            AuthzViolation(
                kind="privilege_escalation",
                endpoint_path="/admin/users",
                endpoint_method="GET",
                persona="user",
                privilege_level="user",
                status_code=200,
            ),
            AuthzViolation(
                kind="inconsistent_authz",
                endpoint_path="/x",
                endpoint_method="GET",
                privilege_level="user",
            ),
        ]

    def test_vuln_class_mapping_is_pinned(self) -> None:
        matrix = _result([], [], _artifact_ref())
        findings = build_authz_candidates(
            self._violations(),
            matrix,
            scan_id="scan-matrix",
            workspace_id="local",
            created_at=_NOW,
        )
        assert [f.vuln_class for f in findings] == [
            VulnerabilityClass.AUTH,
            VulnerabilityClass.AUTH,
            VulnerabilityClass.SECURITY_MISCONFIGURATION,
        ]

    def test_finding_provenance(self) -> None:
        artifact = _artifact_ref()
        matrix = _result([], [], artifact)
        findings = build_authz_candidates(
            self._violations(),
            matrix,
            scan_id="scan-matrix",
            workspace_id="local",
            created_at=_NOW,
        )
        first = findings[0]
        assert first.evidence_refs == [artifact]
        assert first.source_refs and first.source_refs[0].symbol == "anon"
        assert first.metadata["endpoint"] == "/admin/users"

    def test_hunt_tasks_are_deterministic_and_flagged(self) -> None:
        artifact = _artifact_ref()
        matrix = _result([], [], artifact)
        tasks = build_authz_hunt_tasks(
            self._violations(),
            matrix,
            scan_id="scan-matrix",
            round_index=0,
            created_at=_NOW,
        )
        # One task per flagged endpoint (two distinct endpoints here).
        assert len(tasks) == 2
        assert all(t.scope for t in tasks)
        assert all(t.round_index == 0 for t in tasks)
        assert all(t.source == "authz-matrix" for t in tasks)
        assert any(artifact.uri in t.task_prompt for t in tasks)
        assert any("/admin/users" in t.task_prompt for t in tasks)
        again = build_authz_hunt_tasks(
            self._violations(),
            matrix,
            scan_id="scan-matrix",
            round_index=0,
            created_at=_NOW,
        )
        assert [t.id for t in again] == [t.id for t in tasks]
