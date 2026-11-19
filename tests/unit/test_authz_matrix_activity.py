"""Tests for the authz-matrix activity (multi-persona authorization matrix).

The activity probes every attack-map endpoint as every declared persona, using
each persona's pre-resolved ``profile_ref`` as the explicit ``auth_profile``, and
records the HTTP status code plus a content hash of the response body per cell.
These tests pin per-persona request dispatch, status/hash recording, the failure
mode (a transport error is recorded and the matrix continues), deterministic
ordering, and artifact persistence.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import (
    ArtifactKind,
    AuthzMatrixEndpoint,
    AuthzMatrixPersona,
    HttpRequestSpec,
    HttpResponseCapture,
    RedactionStatus,
    TargetEndpoint,
)
from quarry_activities.authz_matrix import authz_matrix_activity
from quarry_activities.inputs import AuthzMatrixActivityInput, HttpRequestActivityInput
from quarry_artifacts.local import LocalArtifactStore

Handler = Callable[[HttpRequestSpec], "tuple[int, str] | Exception"]


class _FakeHttpRequest:
    """Stand-in for ``http_request_activity``: records the specs it receives."""

    def __init__(self, handler: Handler) -> None:
        self._handler = handler
        self.calls: list[HttpRequestSpec] = []

    async def __call__(self, inp: HttpRequestActivityInput) -> HttpResponseCapture:
        spec = HttpRequestSpec.model_validate_json(inp.spec_json)
        self.calls.append(spec)
        outcome = self._handler(spec)
        if isinstance(outcome, Exception):
            raise outcome
        status, body = outcome
        store = LocalArtifactStore(Path(inp.artifact_store_path) / inp.scan_id)
        profile = spec.auth_profile or "anon"
        path = spec.path.strip("/").replace("/", "_") or "root"
        key = f"http/responses/{spec.method}_{path}_{profile}.json"
        store.put_bytes(
            key=key,
            data=json.dumps({"body": body}).encode("utf-8"),
            kind=ArtifactKind.HTTP_RESPONSE,
            content_type="application/json",
        )
        return HttpResponseCapture(
            status_code=status,
            body_artifact_ref="body-ref",
            elapsed_ms=1,
            redaction_status=RedactionStatus.NOT_REQUIRED,
            body_artifact_key=key,
        )


def _endpoint(method: str, path: str) -> AuthzMatrixEndpoint:
    return AuthzMatrixEndpoint(method=method, path=path)


def _persona(
    name: str, profile_ref: str | None, privilege_level: str = "user"
) -> AuthzMatrixPersona:
    return AuthzMatrixPersona(
        name=name,
        profile_ref=profile_ref,
        privilege_level=privilege_level,  # type: ignore[arg-type]
    )


def _input(
    tmp_path: Path,
    endpoints: list[AuthzMatrixEndpoint],
    personas: list[AuthzMatrixPersona],
    do_not_test: tuple[str, ...] = (),
) -> AuthzMatrixActivityInput:
    endpoint = TargetEndpoint(host="app.example.com", port=443, scheme="https")
    return AuthzMatrixActivityInput(
        scan_id="scan-1",
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=("app.example.com",),
        artifact_store_path=str(tmp_path),
        do_not_test=do_not_test,
        endpoints=endpoints,
        personas=personas,
    )


def _patch(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> _FakeHttpRequest:
    fake = _FakeHttpRequest(handler)
    monkeypatch.setattr("quarry_activities.dynamic_http.http_request_activity", fake)
    return fake


async def test_matrix_dimensions_and_deterministic_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _patch(monkeypatch, lambda spec: (200, "ok"))
    personas = [
        _persona("anon", None, "unauthenticated"),
        _persona("admin", "admin-token", "admin"),
    ]
    inp = _input(
        tmp_path,
        [_endpoint("GET", "/z"), _endpoint("POST", "/a"), _endpoint("GET", "/m")],
        personas,
    )

    result = await authz_matrix_activity(inp)

    # Endpoints sorted by path; cells in persona declaration order.
    assert [row.endpoint_path for row in result.rows] == ["/a", "/m", "/z"]
    assert [row.endpoint_method for row in result.rows] == ["POST", "GET", "GET"]
    for row in result.rows:
        assert [cell.persona for cell in row.cells] == ["anon", "admin"]
    # 3 endpoints x 2 personas dispatched.
    assert len(fake.calls) == 6


async def test_cell_records_status_and_body_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = "welcome admin"
    _patch(monkeypatch, lambda spec: (200, body))
    inp = _input(tmp_path, [_endpoint("GET", "/admin")], [_persona("admin", "admin-token")])

    result = await authz_matrix_activity(inp)

    cell = result.rows[0].cells[0]
    assert cell.status_code == 200
    assert cell.error is None
    assert cell.body_hash == sha256(body.encode("utf-8")).hexdigest()


async def test_persona_profile_ref_is_dispatched_as_explicit_auth_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _patch(monkeypatch, lambda spec: (200, "ok"))
    personas = [
        _persona("anon", None, "unauthenticated"),
        _persona("user", "user-token", "user"),
        _persona("admin", "admin-token", "admin"),
    ]
    inp = _input(tmp_path, [_endpoint("GET", "/dashboard")], personas)

    await authz_matrix_activity(inp)

    assert [spec.auth_profile for spec in fake.calls] == [None, "user-token", "admin-token"]


async def test_transport_error_is_recorded_and_matrix_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(spec: HttpRequestSpec) -> tuple[int, str] | Exception:
        if spec.path == "/boom":
            return ConnectionError("connection refused")
        return (200, "ok")

    _patch(monkeypatch, handler)
    inp = _input(
        tmp_path,
        [_endpoint("GET", "/boom"), _endpoint("GET", "/fine")],
        [_persona("user", "user-token")],
    )

    result = await authz_matrix_activity(inp)

    by_path = {row.endpoint_path: row.cells[0] for row in result.rows}
    assert by_path["/boom"].error is not None
    assert "ConnectionError" in by_path["/boom"].error
    assert by_path["/boom"].status_code is None
    # The remaining endpoint is still probed.
    assert by_path["/fine"].status_code == 200


async def test_5xx_status_is_recorded_as_a_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch(monkeypatch, lambda spec: (503, "unavailable"))
    inp = _input(tmp_path, [_endpoint("GET", "/x")], [_persona("user", "user-token")])

    result = await authz_matrix_activity(inp)

    assert result.rows[0].cells[0].status_code == 503


async def test_empty_personas_produces_rows_without_cells(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _patch(monkeypatch, lambda spec: (200, "ok"))
    inp = _input(tmp_path, [_endpoint("GET", "/a")], [])

    result = await authz_matrix_activity(inp)

    assert [row.cells for row in result.rows] == [[]]
    assert fake.calls == []


async def test_matrix_is_persisted_as_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch(monkeypatch, lambda spec: (200, "ok"))
    inp = _input(
        tmp_path,
        [_endpoint("GET", "/a")],
        [_persona("user", "user-token", "user")],
    )

    result = await authz_matrix_activity(inp)

    assert result.artifact_ref is not None
    assert result.artifact_ref.kind == ArtifactKind.AUTHZ_MATRIX
    stored = Path(result.artifact_ref.uri.removeprefix("file://"))
    assert stored.exists()
    payload: dict[str, Any] = json.loads(stored.read_text())
    assert payload["scan_id"] == "scan-1"
    assert [row["endpoint_path"] for row in payload["rows"]] == ["/a"]


async def test_missing_body_artifact_key_records_no_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake(inp: HttpRequestActivityInput) -> HttpResponseCapture:
        return HttpResponseCapture(
            status_code=204,
            body_artifact_ref="body-ref",
            elapsed_ms=1,
            redaction_status=RedactionStatus.NOT_REQUIRED,
            body_artifact_key=None,
        )

    monkeypatch.setattr("quarry_activities.dynamic_http.http_request_activity", fake)
    inp = _input(tmp_path, [_endpoint("GET", "/a")], [_persona("user", "user-token")])

    result = await authz_matrix_activity(inp)

    cell = result.rows[0].cells[0]
    assert cell.status_code == 204
    assert cell.body_hash is None


async def test_endpoint_matching_top_level_do_not_test_produces_no_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The top-level do_not_test ceiling blocks every persona for that path."""
    fake = _patch(monkeypatch, lambda spec: (200, "ok"))
    inp = _input(
        tmp_path,
        [_endpoint("GET", "/admin/users"), _endpoint("GET", "/public")],
        [_persona("anon", None, "unauthenticated"), _persona("admin", "admin-token", "admin")],
        do_not_test=("/admin/*",),
    )

    result = await authz_matrix_activity(inp)

    by_path = {row.endpoint_path: row for row in result.rows}
    assert by_path["/admin/users"].cells == []
    # Only the non-blocked endpoint is probed, once per persona.
    assert [cell.persona for cell in by_path["/public"].cells] == ["anon", "admin"]
    assert len(fake.calls) == 2


def test_activity_is_registered_under_temporal_name() -> None:
    defn = getattr(authz_matrix_activity, "__temporal_activity_definition", None)
    assert defn is not None
    assert defn.name == "authz-matrix"
