"""AuthZ matrix activity — multi-persona authorization testing.

The live-exploitation track historically authenticated every request with a
single ``TargetAuthorization``, so authZ testing was two-user-IDOR-only. This
module adds a *matrix* stage: after live recon produces the attack map, each
endpoint is probed once per declared persona and the resulting
(endpoint × persona) status/hash grid is persisted as a scan artifact.

Layering (workflows → activities):

- Persona *selection* for agent-initiated dispatch lives workflow-side
  (``quarry_workflows.roe.persona_for_request``). This module never selects a
  persona: the workflow pre-resolves the explicit ``profile_ref`` per cell and
  passes it in.
- Probes reuse the shared ``http_request_activity`` implementation — the sole
  egress code path. An activity cannot schedule another activity, so this module
  invokes that coroutine in-process rather than opening its own socket; that
  keeps the single egress path the repo maintains (ADR-017).

This module performs no violation detection and emits no findings: it only
measures and records the matrix. Detection lives in a later stage.
"""

from __future__ import annotations

import json
from contextlib import suppress
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast

from temporalio import activity

from quarry.schemas import (
    ArtifactKind,
    AuthzMatrixCell,
    AuthzMatrixEndpoint,
    AuthzMatrixPersona,
    AuthzMatrixResult,
    AuthzMatrixRow,
    HttpRequestSpec,
    HttpResponseCapture,
    TargetEndpoint,
)
from quarry_activities.inputs import AuthzMatrixActivityInput, HttpRequestActivityInput
from quarry_artifacts.local import LocalArtifactStore

HttpMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

_HTTP_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
)


@activity.defn(name="authz-matrix")
async def authz_matrix_activity(inp: AuthzMatrixActivityInput) -> AuthzMatrixResult:
    """Probe every endpoint as every persona and persist the resulting matrix.

    Deterministic ordering: endpoints sorted by path, personas in declaration
    order. Each cell records the HTTP status code and a hash of the response
    body; a transport error is recorded as the cell's ``error`` and the matrix
    continues with the remaining cells. The result is persisted as a scan
    artifact and returned with its ``ArtifactRef`` for provenance.
    """
    endpoint = TargetEndpoint.model_validate_json(inp.target_endpoint_json)
    store = LocalArtifactStore(Path(inp.artifact_store_path) / inp.scan_id)

    rows: list[AuthzMatrixRow] = []
    for ep in sorted(inp.endpoints, key=lambda e: e.path):
        cells: list[AuthzMatrixCell] = []
        for persona in inp.personas:
            with suppress(RuntimeError):
                activity.heartbeat()
            cells.append(await _probe_cell(inp, endpoint, ep, persona, store))
        rows.append(AuthzMatrixRow(endpoint_path=ep.path, endpoint_method=ep.method, cells=cells))

    result = AuthzMatrixResult(scan_id=inp.scan_id, personas=list(inp.personas), rows=rows)
    artifact_ref = store.put_json(
        key="authz_matrix/matrix.json",
        data=result,
        kind=ArtifactKind.AUTHZ_MATRIX,
        metadata={
            "scan_id": inp.scan_id,
            "endpoint_count": len(rows),
            "persona_count": len(inp.personas),
        },
    )
    return result.model_copy(update={"artifact_ref": artifact_ref})


async def _probe_cell(
    inp: AuthzMatrixActivityInput,
    endpoint: TargetEndpoint,
    ep: AuthzMatrixEndpoint,
    persona: AuthzMatrixPersona,
    store: LocalArtifactStore,
) -> AuthzMatrixCell:
    """Dispatch one (endpoint, persona) probe via the shared http-request path.

    The persona's pre-resolved ``profile_ref`` becomes the request's explicit
    ``auth_profile`` (``None`` = unauthenticated, no credential injection).

    ``http_request_activity`` is imported locally: it is the sole egress code
    path, and importing it at module scope would re-expose the decorated
    function to the activity registry (duplicate ``http-request`` name).
    """
    from quarry_activities.dynamic_http import http_request_activity

    spec = HttpRequestSpec(
        method=_normalise_method(ep.method),
        path=ep.path,
        auth_profile=persona.profile_ref,
    )
    request_input = HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=inp.allowed_hosts,
        artifact_store_path=inp.artifact_store_path,
        scan_id=inp.scan_id,
        candidate_finding_id=f"authz-matrix-{persona.name}",
        auth_profile_set_json=inp.auth_profile_set_json,
    )
    try:
        capture = await http_request_activity(request_input)
    except Exception as exc:  # transport failure — record the cell, continue
        return AuthzMatrixCell(persona=persona.name, error=f"{type(exc).__name__}: {exc}")

    return AuthzMatrixCell(
        persona=persona.name,
        status_code=capture.status_code,
        body_hash=_body_hash(store, capture),
    )


def _body_hash(store: LocalArtifactStore, capture: HttpResponseCapture) -> str | None:
    """Content hash of the captured response body, or ``None`` when unavailable."""
    if not capture.body_artifact_key:
        return None
    raw = store.get_text(capture.body_artifact_key)
    if raw is None:
        return None
    return sha256(_artifact_body(raw).encode("utf-8")).hexdigest()


def _artifact_body(raw: str) -> str:
    """Extract the response body from a stored http-response artifact JSON.

    Falls back to the raw text when the artifact is not the expected JSON shape,
    so a body hash is always recorded (never a hard failure).
    """
    try:
        parsed: object = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    if isinstance(parsed, dict):
        mapping = cast("dict[str, object]", parsed)
        body = mapping.get("body")
        if isinstance(body, str):
            return body
    return raw


def _normalise_method(method: str) -> HttpMethod:
    """Coerce an attack-map method to an ``HttpRequestSpec`` literal (GET default)."""
    upper = method.strip().upper()
    if upper in _HTTP_METHODS:
        return cast("HttpMethod", upper)
    return "GET"


__all__ = ["authz_matrix_activity"]
