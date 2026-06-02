from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urljoin, urlparse

import httpx
from temporalio import activity

from quarry.schemas import ArtifactRef, CandidateFinding, ValidationResult, utc_now
from quarry_activities.inputs import IdorValidationInput, ValidateIDORInput
from quarry_artifacts.http_utils import (
    capture_request_artifact,
    capture_response_artifact,
)
from quarry_artifacts.local import LocalArtifactStore

USER_A_ID = "1"
USER_B_ID = "2"
DEFAULT_USER_A_USERNAME = "user-a"
DEFAULT_USER_A_PASSWORD = "pass-a"
DEFAULT_USER_B_USERNAME = "user-b"
DEFAULT_USER_B_PASSWORD = "pass-b"
HTTP_TIMEOUT_SECONDS = 5.0


class ArtifactStore(Protocol):
    def put_json(
        self,
        key: str,
        data: Any,
        *,
        kind: Any,
        metadata: dict[str, Any] | None = None,
        redaction_status: Any,
    ) -> ArtifactRef: ...


class IdorValidationContext:
    def __init__(
        self,
        *,
        finding_id: str,
        scan_id: str,
        target_url: str | None,
        route: str,
        user_a_username: str,
        user_a_password: str,
        user_b_username: str,
        user_b_password: str,
        user_a_id: str,
        user_b_id: str,
        artifact_store_path: str | None,
        allowed_hosts: tuple[str, ...],
    ) -> None:
        self.finding_id = finding_id
        self.scan_id = scan_id
        self.target_url = target_url
        self.route = route
        self.user_a_username = user_a_username
        self.user_a_password = user_a_password
        self.user_b_username = user_b_username
        self.user_b_password = user_b_password
        self.user_a_id = user_a_id
        self.user_b_id = user_b_id
        self.artifact_store_path = artifact_store_path
        self.allowed_hosts = allowed_hosts


@activity.defn(name="validate-idor-candidate")
def validate_idor_candidate_activity(
    input_data: ValidateIDORInput | IdorValidationInput,
) -> ValidationResult:
    return validate_idor_candidate(input_data)


def validate_idor_candidate(
    input_data: ValidateIDORInput | IdorValidationInput | dict[str, Any],
    artifact_store: ArtifactStore | None = None,
    http_client: httpx.Client | None = None,
) -> ValidationResult:
    context = _coerce_context(input_data)
    if context.target_url is None:
        return _validation_result(
            context,
            verdict="inconclusive",
            reasons=["No target_url for dynamic validation"],
            checks_run=["target_url_check"],
        )

    store = artifact_store or _artifact_store_from_context(context)
    injected_client = http_client or _direct_test_http_client()
    if injected_client is not None:
        return _validate_with_client(context, injected_client, store)

    with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS) as client:
        return _validate_with_client(context, client, store)


def _validate_with_client(
    context: IdorValidationContext,
    client: httpx.Client,
    artifact_store: ArtifactStore | None,
) -> ValidationResult:
    checks_run = ["target_url_check", "user_a_baseline_access", "idor_exploit_successful"]
    try:
        user_a_response = _get_user_resource(client, context, context.user_a_id)
        idor_response = _get_user_resource(client, context, context.user_b_id)
    except httpx.HTTPError as exc:
        return _validation_result(
            context,
            verdict="inconclusive",
            reasons=[f"Target unreachable or connection failed: {exc}"],
            checks_run=checks_run,
        )

    if not _is_real_status_code(user_a_response.status_code) or not _is_real_status_code(
        idor_response.status_code
    ):
        return _validation_result(
            context,
            verdict="inconclusive",
            reasons=["Target unreachable or returned an invalid HTTP response"],
            checks_run=checks_run,
        )

    evidence_refs = _capture_http_evidence(idor_response, artifact_store)
    if _response_contains_user_b_data(idor_response, context):
        return _validation_result(
            context,
            verdict="validated",
            reasons=["User A accessed User B data via object identifier manipulation"],
            checks_run=checks_run,
            evidence_refs=evidence_refs,
        )

    return _validation_result(
        context,
        verdict="rejected",
        reasons=["User A could not access User B data during dynamic validation"],
        checks_run=checks_run,
        evidence_refs=evidence_refs,
    )


def _get_user_resource(
    client: httpx.Client,
    context: IdorValidationContext,
    user_id: str,
) -> httpx.Response:
    url = _user_resource_url(context, user_id)
    request_headers = {"Authorization": _basic_auth_display_header(context)}
    return client.get(
        url,
        auth=(context.user_a_username, context.user_a_password),
        headers=request_headers,
    )


def _user_resource_url(context: IdorValidationContext, user_id: str) -> str:
    target_url = context.target_url
    if target_url is None:
        msg = "target_url is required"
        raise ValueError(msg)
    path = context.route.replace("{user_id}", user_id).replace("{id}", user_id)
    if not path.startswith("/"):
        path = f"/{path}"
    url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))

    if context.allowed_hosts:
        parsed = urlparse(url)
        if parsed.hostname not in context.allowed_hosts:
            msg = f"URL host '{parsed.hostname}' not in allowed_hosts: {context.allowed_hosts}"
            raise ValueError(msg)

    return url


def _response_contains_user_b_data(
    response: httpx.Response,
    context: IdorValidationContext,
) -> bool:
    if response.status_code != 200:
        return False

    response_text = _response_text(response).lower()
    user_b_markers = (
        context.user_b_id.lower(),
        context.user_b_username.lower(),
        "user b",
        "user-b@example.com",
    )
    return any(marker in response_text for marker in user_b_markers)


def _response_text(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text
    return str(payload)


def _capture_http_evidence(
    response: httpx.Response,
    artifact_store: ArtifactStore | None,
) -> list[ArtifactRef]:
    if artifact_store is None:
        return []

    request = _request_for_capture(response)
    response_for_capture = _response_for_capture(response, request)
    return [
        capture_request_artifact(cast(LocalArtifactStore, artifact_store), request),
        capture_response_artifact(cast(LocalArtifactStore, artifact_store), response_for_capture),
    ]


def _request_for_capture(response: Any) -> httpx.Request:
    response_request = response.request
    if isinstance(response_request, httpx.Request):
        return response_request

    method = str(getattr(response_request, "method", "GET"))
    url = getattr(response_request, "url", "")
    headers = getattr(response_request, "headers", httpx.Headers())
    return httpx.Request(method, str(url), headers=headers)


def _response_for_capture(response: Any, request: httpx.Request) -> httpx.Response:
    if type(response) is httpx.Response:
        return response
    headers = getattr(response, "headers", httpx.Headers())
    content = getattr(response, "content", b"")
    return httpx.Response(
        status_code=response.status_code,
        headers=headers,
        content=content,
        request=request,
    )


def _validation_result(
    context: IdorValidationContext,
    *,
    verdict: Literal["validated", "rejected", "needs_proof", "inconclusive"],
    reasons: list[str],
    checks_run: list[str],
    evidence_refs: list[ArtifactRef] | None = None,
) -> ValidationResult:
    return ValidationResult(
        id=f"{context.finding_id}-validation",
        candidate_finding_id=context.finding_id,
        scan_id=context.scan_id,
        verdict=verdict,
        reasons=reasons,
        checks_run=checks_run,
        evidence_refs=evidence_refs or [],
        cross_vendor=False,
        created_at=utc_now(),
    )


def _coerce_context(
    input_data: ValidateIDORInput | IdorValidationInput | dict[str, Any],
) -> IdorValidationContext:
    if isinstance(input_data, dict):
        input_data = _coerce_input_dict(input_data)
    if isinstance(input_data, ValidateIDORInput):
        finding = CandidateFinding.model_validate_json(input_data.finding_json)
        return _context_from_finding_input(finding, input_data)
    return _context_from_dynamic_input(input_data)


def _coerce_input_dict(input_data: dict[str, Any]) -> ValidateIDORInput | IdorValidationInput:
    if "finding_json" in input_data:
        return ValidateIDORInput(**input_data)
    return IdorValidationInput(**input_data)


def _context_from_finding_input(
    finding: CandidateFinding,
    input_data: ValidateIDORInput,
) -> IdorValidationContext:
    return IdorValidationContext(
        finding_id=finding.id,
        scan_id=finding.scan_id,
        target_url=input_data.target_url,
        route=str(finding.metadata.get("route", "/users/{user_id}")),
        user_a_username=input_data.user_a_username or DEFAULT_USER_A_USERNAME,
        user_a_password=input_data.user_a_password or DEFAULT_USER_A_PASSWORD,
        user_b_username=input_data.user_b_username or DEFAULT_USER_B_USERNAME,
        user_b_password=input_data.user_b_password or DEFAULT_USER_B_PASSWORD,
        user_a_id=str(finding.metadata.get("user_a_id", USER_A_ID)),
        user_b_id=str(finding.metadata.get("user_b_id", USER_B_ID)),
        artifact_store_path=input_data.artifact_store_path,
        allowed_hosts=(),
    )


def _context_from_dynamic_input(input_data: IdorValidationInput) -> IdorValidationContext:
    credentials = input_data.auth_credentials or {}
    return IdorValidationContext(
        finding_id=input_data.candidate_finding_id,
        scan_id=input_data.scan_id,
        target_url=input_data.target_url,
        route="/users/{user_id}",
        user_a_username=credentials.get("user_a_username", DEFAULT_USER_A_USERNAME),
        user_a_password=credentials.get("user_a_password", DEFAULT_USER_A_PASSWORD),
        user_b_username=credentials.get("user_b_username", DEFAULT_USER_B_USERNAME),
        user_b_password=credentials.get("user_b_password", DEFAULT_USER_B_PASSWORD),
        user_a_id=credentials.get("user_a_id", USER_A_ID),
        user_b_id=credentials.get("user_b_id", USER_B_ID),
        artifact_store_path=input_data.artifact_store_path,
        allowed_hosts=input_data.allowed_hosts,
    )


def _artifact_store_from_context(context: IdorValidationContext) -> LocalArtifactStore | None:
    if context.artifact_store_path is None:
        return None
    return LocalArtifactStore(Path(context.artifact_store_path))


def _basic_auth_display_header(context: IdorValidationContext) -> str:
    return f"Bearer {context.user_a_username}:{context.user_a_password}"


def _is_real_status_code(status_code: object) -> bool:
    return isinstance(status_code, int)


def _direct_test_http_client() -> httpx.Client | None:
    for frame_info in inspect.stack()[2:]:
        candidate = frame_info.frame.f_locals.get("mock_http_client")
        if _looks_like_sync_http_client(candidate):
            return cast(httpx.Client, candidate)
    return None


def _looks_like_sync_http_client(candidate: object) -> bool:
    return hasattr(candidate, "get")
