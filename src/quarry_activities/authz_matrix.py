"""AuthZ matrix activity — multi-persona authorization testing (W14).

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
- The activity dispatches every probe through the shared
  ``http_request_activity`` implementation (the sole egress code path). An
  activity cannot schedule another activity, so it invokes that coroutine
  in-process — the alternative (opening its own socket) would duplicate the
  egress path the repo keeps in one place.
- Violation detection and the candidate/hunt-task builders are pure functions
  (no I/O), so the workflow can import and run them inside its sandbox.

Detection is *declared ground truth* only: a 2xx cell on a path matching a
persona's ``expected_denied_paths`` is a violation (``unauth_access`` for the
unauthenticated persona, ``privilege_escalation`` otherwise); two
same-``privilege_level`` personas receiving different status classes on one
endpoint is ``inconsistent_authz``. Body hashes are recorded as evidence but
never trigger a finding, and error/5xx cells are inconclusive.
"""

from __future__ import annotations

import json
import time
from contextlib import suppress
from datetime import datetime
from fnmatch import fnmatch
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel
from temporalio import activity

from quarry.schemas import (
    AgentTask,
    ArtifactKind,
    ArtifactRef,
    AuthzMatrixCell,
    AuthzMatrixEndpoint,
    AuthzMatrixPersona,
    AuthzMatrixResult,
    AuthzMatrixRow,
    CandidateFinding,
    Confidence,
    FindingStatus,
    HttpRequestSpec,
    HttpResponseCapture,
    Severity,
    SourceRef,
    TargetEndpoint,
    VulnerabilityClass,
)
from quarry_activities.inputs import AuthzMatrixActivityInput, HttpRequestActivityInput
from quarry_artifacts.local import LocalArtifactStore

AuthzViolationKind = Literal["unauth_access", "privilege_escalation", "inconsistent_authz"]
HttpMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# Finding classification is pinned to existing VulnerabilityClass members — no
# new member is introduced (W14 spec requirement).
_UNAUTH_ACCESS = "unauth_access"
_PRIVILEGE_ESCALATION = "privilege_escalation"
_INCONSISTENT_AUTHZ = "inconsistent_authz"

_HTTP_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
)


class AuthzViolation(BaseModel):
    """One detected authorization violation (declared ground truth only)."""

    kind: AuthzViolationKind
    endpoint_path: str
    endpoint_method: str
    persona: str | None = None
    privilege_level: str | None = None
    status_code: int | None = None
    detail: str = ""


# ---------------------------------------------------------------------------
# Activity
# ---------------------------------------------------------------------------


@activity.defn(name="authz-matrix")
async def authz_matrix_activity(inp: AuthzMatrixActivityInput) -> AuthzMatrixResult:
    """Probe every endpoint as every persona and persist the resulting matrix.

    Deterministic ordering: endpoints sorted by path, personas in declaration
    order. Each cell records the HTTP status code and a hash of the response
    body; a transport error or a refused dispatch is recorded as the cell's
    ``error`` and the matrix continues. The result is persisted as a scan
    artifact and returned with its ``ArtifactRef`` for provenance.
    """
    endpoint = TargetEndpoint.model_validate_json(inp.target_endpoint_json)
    store = LocalArtifactStore(Path(inp.artifact_store_path) / inp.scan_id)

    rows: list[AuthzMatrixRow] = []
    last_request_at: float | None = None
    for ep in sorted(inp.endpoints, key=lambda e: e.path):
        cells: list[AuthzMatrixCell] = []
        for persona in inp.personas:
            last_request_at = _pace(last_request_at, inp.min_request_interval_seconds)
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


def _pace(last_request_at: float | None, min_interval: float) -> float:
    """Sleep so consecutive requests to one host are at least *min_interval* apart.

    Returns the monotonic timestamp after the (possible) sleep.
    """
    now = time.monotonic()
    if last_request_at is not None and min_interval > 0:
        remaining = min_interval - (now - last_request_at)
        if remaining > 0:
            time.sleep(remaining)
            now = time.monotonic()
    return now


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
    except Exception as exc:  # transport failure / refused dispatch — record, continue
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


# ---------------------------------------------------------------------------
# Violation detection — declared ground truth only (pure)
# ---------------------------------------------------------------------------


def _is_2xx(status_code: int) -> bool:
    return 200 <= status_code < 300


def _path_matches(path: str, pattern: str) -> bool:
    """The ``do_not_test`` matching convention: glob or exact/prefix."""
    if fnmatch(path, pattern):
        return True
    prefix = pattern.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def _path_matches_any(path: str, patterns: list[str]) -> bool:
    return any(_path_matches(path, pattern) for pattern in patterns)


def _is_inconclusive(cell: AuthzMatrixCell) -> bool:
    """A cell with a transport error or a 5xx status is inconclusive for every rule."""
    if cell.error is not None or cell.status_code is None:
        return True
    return cell.status_code >= 500


def detect_authz_violations(matrix: AuthzMatrixResult) -> list[AuthzViolation]:
    """Apply the declared-ground-truth rules to *matrix* (pure, deterministic).

    Rules (spec: "Violation detection uses declared ground truth"):

    1. ``declared-denied access``: a 2xx cell on a path matching *that persona's*
       ``expected_denied_paths``. ``unauth_access`` for the unauthenticated
       persona, ``privilege_escalation`` otherwise. A 2xx on an undeclared path
       raises nothing (public endpoints must not flood findings).
    2. ``inconsistent authZ``: two personas sharing a ``privilege_level``
       receiving different status classes (2xx vs 3xx/4xx) on one endpoint.

    Both rules are inert-by-declaration: with no unauthenticated persona the
    first can never fire; with no ``expected_denied_paths`` declared anywhere it
    raises nothing. Neither state is an error.
    """
    personas = {p.name: p for p in matrix.personas}
    violations: list[AuthzViolation] = []

    for row in matrix.rows:
        for cell in row.cells:
            if _is_inconclusive(cell):
                continue
            persona = personas.get(cell.persona)
            if persona is None or cell.status_code is None:
                continue
            if not _is_2xx(cell.status_code):
                continue
            if not _path_matches_any(row.endpoint_path, persona.expected_denied_paths):
                continue
            kind: AuthzViolationKind = (
                _UNAUTH_ACCESS
                if persona.privilege_level == "unauthenticated"
                else _PRIVILEGE_ESCALATION
            )
            violations.append(
                AuthzViolation(
                    kind=kind,
                    endpoint_path=row.endpoint_path,
                    endpoint_method=row.endpoint_method,
                    persona=cell.persona,
                    privilege_level=persona.privilege_level,
                    status_code=cell.status_code,
                    detail=(
                        f"{persona.privilege_level} persona '{persona.name}' received "
                        f"{cell.status_code} on declared-denied path {row.endpoint_path}"
                    ),
                )
            )

        # Group conclusive cells by the persona's declared privilege level.
        by_privilege: dict[str, list[tuple[str, str]]] = {}
        for cell in row.cells:
            if _is_inconclusive(cell):
                continue
            persona = personas.get(cell.persona)
            if persona is None or cell.status_code is None:
                continue
            status_class = "2xx" if _is_2xx(cell.status_code) else "other"
            by_privilege.setdefault(persona.privilege_level, []).append(
                (cell.persona, status_class)
            )

        for privilege_level, entries in by_privilege.items():
            if len(entries) < 2:
                continue
            if len({status_class for _, status_class in entries}) < 2:
                continue
            violations.append(
                AuthzViolation(
                    kind=_INCONSISTENT_AUTHZ,
                    endpoint_path=row.endpoint_path,
                    endpoint_method=row.endpoint_method,
                    persona=None,
                    privilege_level=privilege_level,
                    detail=(
                        f"personas at privilege_level '{privilege_level}' received "
                        f"different status classes on {row.endpoint_path}"
                    ),
                )
            )

    return violations


# ---------------------------------------------------------------------------
# Candidate-finding / hunt-task emission (pure builders — caller supplies now())
# ---------------------------------------------------------------------------


def _authz_finding_id(violation: AuthzViolation) -> str:
    raw = "|".join(
        (
            "authz-matrix",
            violation.kind,
            violation.endpoint_method,
            violation.endpoint_path,
            violation.persona or "-",
            violation.privilege_level or "-",
        )
    )
    return sha256(raw.encode("utf-8")).hexdigest()[:32]


def _persona_source_ref(persona_name: str | None) -> SourceRef:
    return SourceRef(
        file_path="auth-profiles.toml",
        symbol=persona_name or "personas",
    )


def build_authz_candidates(
    violations: list[AuthzViolation],
    matrix: AuthzMatrixResult,
    *,
    scan_id: str,
    workspace_id: str,
    created_at: datetime,
) -> list[CandidateFinding]:
    """Turn each violation into a first-class ``CandidateFinding`` (pure).

    ``vuln_class`` is pinned to existing enum members: ``unauth_access`` and
    ``privilege_escalation`` → ``AUTH``; ``inconsistent_authz`` →
    ``SECURITY_MISCONFIGURATION``. ``evidence_refs`` carries the matrix artifact
    and ``source_refs`` the persona declaration.
    """
    evidence_refs: list[ArtifactRef] = (
        [matrix.artifact_ref] if matrix.artifact_ref is not None else []
    )
    findings: list[CandidateFinding] = []
    for violation in violations:
        if violation.kind in (_UNAUTH_ACCESS, _PRIVILEGE_ESCALATION):
            vuln_class = VulnerabilityClass.AUTH
        else:
            vuln_class = VulnerabilityClass.SECURITY_MISCONFIGURATION
        persona_label = violation.persona or violation.privilege_level or "unknown"
        findings.append(
            CandidateFinding(
                id=_authz_finding_id(violation),
                scan_id=scan_id,
                workspace_id=workspace_id,
                vuln_class=vuln_class,
                title=(
                    f"Authorization violation ({violation.kind}) on "
                    f"{violation.endpoint_method} {violation.endpoint_path}"
                ),
                hypothesis=(
                    f"Persona '{persona_label}' reached "
                    f"{violation.endpoint_method} {violation.endpoint_path} contrary to "
                    f"the declared authorization policy ({violation.detail})."
                ),
                confidence=Confidence.MEDIUM,
                severity=Severity.HIGH,
                status=FindingStatus.CANDIDATE,
                created_by="authz-matrix",
                created_at=created_at,
                evidence_refs=evidence_refs,
                source_refs=[_persona_source_ref(violation.persona)],
                metadata={
                    "source": "authz-matrix",
                    "violation_kind": violation.kind,
                    "persona": violation.persona,
                    "privilege_level": violation.privilege_level,
                    "endpoint": violation.endpoint_path,
                    "endpoint_method": violation.endpoint_method,
                },
            )
        )
    return findings


def build_authz_hunt_tasks(
    violations: list[AuthzViolation],
    matrix: AuthzMatrixResult,
    *,
    scan_id: str,
    round_index: int,
    created_at: datetime,
) -> list[AgentTask]:
    """Create one hunt ``AgentTask`` per flagged endpoint (gapfill/feedback shape).

    Pure: ids derive deterministically from the endpoint, so replay mints the
    same tasks. Deduplication against hunted cells happens caller-side via
    ``dedup_new_tasks`` (``cell_key`` = ``(scope, vuln_class, source)``).
    """
    artifact_uri = matrix.artifact_ref.uri if matrix.artifact_ref is not None else "(none)"
    tasks: list[AgentTask] = []
    seen: set[str] = set()
    for violation in violations:
        cell = f"{violation.endpoint_method} {violation.endpoint_path}"
        if cell in seen:
            continue
        seen.add(cell)
        vuln_class = (
            VulnerabilityClass.AUTH
            if violation.kind in (_UNAUTH_ACCESS, _PRIVILEGE_ESCALATION)
            else VulnerabilityClass.SECURITY_MISCONFIGURATION
        )
        persona_label = violation.persona or violation.privilege_level or "unknown"
        task_id = sha256(f"authz-matrix-task|{cell}".encode()).hexdigest()[:32]
        tasks.append(
            AgentTask(
                id=task_id,
                scan_id=scan_id,
                role="hunt",
                task_name=(f"authz-matrix-{violation.endpoint_path.strip('/').replace('/', '-')}"),
                task_prompt=(
                    f"Authorization violation on {cell}: persona '{persona_label}' "
                    f"({violation.kind}) was granted access contrary to the declared "
                    f"policy. Investigate the route-level authorization for this "
                    f"endpoint and any related endpoints. Matrix artifact: {artifact_uri}."
                ),
                vuln_class=vuln_class,
                scope=violation.endpoint_path,
                source="gapfill",
                round_index=round_index,
                status="pending",
                created_at=created_at,
            )
        )
    return tasks


__all__ = [
    "AuthzMatrixActivityInput",
    "AuthzMatrixCell",
    "AuthzMatrixEndpoint",
    "AuthzMatrixPersona",
    "AuthzMatrixResult",
    "AuthzMatrixRow",
    "AuthzViolation",
    "authz_matrix_activity",
    "build_authz_candidates",
    "build_authz_hunt_tasks",
    "detect_authz_violations",
]
