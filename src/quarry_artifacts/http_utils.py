"""HTTP request/response artifact capture utilities."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

import httpx

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus
from quarry_artifacts.local import LocalArtifactStore

# Maximum response body size to store (10KB)
MAX_RESPONSE_BODY_SIZE = 10 * 1024


def _key_digest(*parts: str) -> str:
    """Short stable digest so artifacts for different requests don't collide."""
    return sha256(" ".join(parts).encode("utf-8")).hexdigest()[:12]


def _redact_headers(headers: httpx.Headers) -> dict[str, str | list[str]]:
    """Redact sensitive header values before storing.

    Authorization header values are replaced with 'REDACTED'.
    Other headers are preserved as-is.
    """
    redacted: dict[str, str | list[str]] = {}
    for key, value in headers.multi_items():
        if key.lower() == "authorization":
            redacted["Authorization"] = "REDACTED"
        elif key in redacted:
            # Handle multi-value headers
            existing = redacted[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                redacted[key] = [existing, value]
        else:
            redacted[key] = value
    return redacted


def _truncate_body(body: bytes, max_size: int = MAX_RESPONSE_BODY_SIZE) -> tuple[bytes, bool]:
    """Truncate body to max_size bytes.

    Returns (truncated_body, was_truncated).
    """
    if len(body) <= max_size:
        return body, False
    return body[:max_size], True


def capture_request_artifact(
    store: LocalArtifactStore,
    request: httpx.Request,
    artifact_key: str | None = None,
) -> ArtifactRef:
    """Serialize an httpx.Request to JSON artifact and store it.

    Authorization header values are redacted before storage.

    Args:
        store: LocalArtifactStore instance
        request: httpx.Request to capture
        artifact_key: Optional storage key (auto-generated if not provided)

    Returns:
        ArtifactRef for the stored request artifact
    """
    if artifact_key is None:
        digest = _key_digest(request.method, str(request.url))
        artifact_key = f"http/requests/{request.method}_{request.url.host}_{digest}.json"

    # Build request data with redacted headers
    request_data: dict[str, Any] = {
        "method": request.method,
        "url": str(request.url),
        "headers": _redact_headers(request.headers),
    }

    # Include body if present
    if request.content:
        request_data["body"] = request.content.decode("utf-8", errors="replace")

    # Create a temporary model to serialize
    from pydantic import BaseModel

    class RequestArtifact(BaseModel):
        method: str
        url: str
        headers: dict[str, str | list[str]]
        body: str | None = None

    artifact_model = RequestArtifact(**request_data)

    return store.put_json(
        key=artifact_key,
        data=artifact_model,
        kind=ArtifactKind.HTTP_REQUEST,
        metadata={
            "method": request.method,
            "host": request.url.host,
        },
        redaction_status=RedactionStatus.REDACTED,
    )


def capture_response_artifact(
    store: LocalArtifactStore,
    response: httpx.Response,
    artifact_key: str | None = None,
) -> ArtifactRef:
    """Serialize an httpx.Response to JSON artifact and store it.

    Response body is truncated to 10KB max.

    Args:
        store: LocalArtifactStore instance
        response: httpx.Response to capture
        artifact_key: Optional storage key (auto-generated if not provided)

    Returns:
        ArtifactRef for the stored response artifact
    """
    if artifact_key is None:
        digest = _key_digest(str(response.status_code), str(response.request.url))
        host = response.request.url.host
        artifact_key = f"http/responses/{response.status_code}_{host}_{digest}.json"

    # Truncate body if needed
    body_bytes = response.content
    truncated_body, was_truncated = _truncate_body(body_bytes)

    # Build response data
    response_data: dict[str, Any] = {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "url": str(response.url),
        "body": truncated_body.decode("utf-8", errors="replace"),
        "truncated": was_truncated,
        "original_size": len(body_bytes),
    }

    # Create a temporary model to serialize
    from pydantic import BaseModel

    class ResponseArtifact(BaseModel):
        status_code: int
        headers: dict[str, str]
        url: str
        body: str
        truncated: bool
        original_size: int

    artifact_model = ResponseArtifact(**response_data)

    redaction_status = (
        RedactionStatus.CONTAINS_SENSITIVE if was_truncated else RedactionStatus.NOT_REQUIRED
    )

    return store.put_json(
        key=artifact_key,
        data=artifact_model,
        kind=ArtifactKind.HTTP_RESPONSE,
        metadata={
            "status_code": response.status_code,
            "host": response.request.url.host,
            "truncated": was_truncated,
            "original_size": len(body_bytes),
        },
        redaction_status=redaction_status,
    )
