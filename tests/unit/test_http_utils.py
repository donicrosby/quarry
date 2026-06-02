"""Tests for HTTP request/response artifact capture utilities."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from quarry.schemas import ArtifactKind, RedactionStatus
from quarry_artifacts.http_utils import (
    MAX_RESPONSE_BODY_SIZE,
    capture_request_artifact,
    capture_response_artifact,
)
from quarry_artifacts.local import LocalArtifactStore


@pytest.fixture
def store(tmp_path: Path) -> LocalArtifactStore:
    """Create a temporary LocalArtifactStore."""
    return LocalArtifactStore(tmp_path)


def test_request_artifact_redacts_auth(store: LocalArtifactStore) -> None:
    """Authorization header is redacted before storage."""
    # Create a request with Authorization header
    request = httpx.Request(
        method="POST",
        url="https://api.example.com/secret",
        headers={
            "Authorization": "Bearer super-secret-token-12345",
            "Content-Type": "application/json",
            "X-Custom-Header": "custom-value",
        },
        content=b'{"test": "data"}',
    )

    # Capture the request artifact
    artifact_ref = capture_request_artifact(store, request)

    # Verify redaction status
    assert artifact_ref.redaction_status == RedactionStatus.REDACTED
    assert artifact_ref.kind == ArtifactKind.HTTP_REQUEST

    # Read back the stored artifact and verify Authorization is redacted
    stored_bytes = store.get_bytes(artifact_ref)
    stored_json = stored_bytes.decode("utf-8")

    assert "super-secret-token-12345" not in stored_json
    assert "REDACTED" in stored_json
    assert "content-type" in stored_json
    assert "x-custom-header" in stored_json


def test_response_artifact_truncates_body(store: LocalArtifactStore) -> None:
    """Response body is truncated to 10KB max."""
    # Create a response with a body larger than 10KB
    large_body = b"x" * (MAX_RESPONSE_BODY_SIZE + 1000)  # 10KB + 1000 bytes

    request = httpx.Request("GET", "https://api.example.com/data")
    response = httpx.Response(
        status_code=200,
        request=request,
        headers={"Content-Type": "application/json"},
        content=large_body,
    )

    # Capture the response artifact
    artifact_ref = capture_response_artifact(store, response)

    # Verify truncation metadata
    assert artifact_ref.metadata["truncated"] is True
    assert artifact_ref.metadata["original_size"] == len(large_body)
    assert artifact_ref.kind == ArtifactKind.HTTP_RESPONSE

    # Read back the stored artifact
    stored_bytes = store.get_bytes(artifact_ref)
    stored_json = stored_bytes.decode("utf-8")

    # Verify body was truncated
    assert len(stored_bytes) < len(large_body)
    assert '"truncated": true' in stored_json
    assert f'"original_size": {len(large_body)}' in stored_json


def test_response_artifact_no_truncation_for_small_body(store: LocalArtifactStore) -> None:
    """Small response bodies are not truncated."""
    small_body = b'{"message": "hello"}'

    request = httpx.Request("GET", "https://api.example.com/data")
    response = httpx.Response(
        status_code=200,
        request=request,
        headers={"Content-Type": "application/json"},
        content=small_body,
    )

    artifact_ref = capture_response_artifact(store, response)

    assert artifact_ref.metadata["truncated"] is False
    assert artifact_ref.metadata["original_size"] == len(small_body)
    assert artifact_ref.redaction_status == RedactionStatus.NOT_REQUIRED


def test_artifact_ref_returned(store: LocalArtifactStore) -> None:
    """Functions return valid ArtifactRef objects."""
    # Test request artifact
    request = httpx.Request(
        method="GET",
        url="https://api.example.com/test",
        headers={"Accept": "application/json"},
    )

    request_ref = capture_request_artifact(store, request)

    assert request_ref.id is not None
    assert request_ref.uri.startswith("file://")
    assert request_ref.kind == ArtifactKind.HTTP_REQUEST
    assert request_ref.content_type == "application/json"
    assert request_ref.sha256 is not None
    assert request_ref.size_bytes > 0
    assert request_ref.created_at is not None

    # Test response artifact
    response = httpx.Response(
        status_code=200,
        request=httpx.Request("GET", "https://api.example.com/test"),
        headers={"Content-Type": "application/json"},
        content=b'{"result": "ok"}',
    )

    response_ref = capture_response_artifact(store, response)

    assert response_ref.id is not None
    assert response_ref.uri.startswith("file://")
    assert response_ref.kind == ArtifactKind.HTTP_RESPONSE
    assert response_ref.content_type == "application/json"
    assert response_ref.sha256 is not None
    assert response_ref.size_bytes > 0
    assert response_ref.created_at is not None


def test_request_artifact_custom_key(store: LocalArtifactStore) -> None:
    """Custom artifact key is used when provided."""
    request = httpx.Request(
        method="POST",
        url="https://api.example.com/endpoint",
        headers={},
    )

    custom_key = "custom/path/to/artifact.json"
    artifact_ref = capture_request_artifact(store, request, artifact_key=custom_key)

    # Verify the artifact is stored at the custom path
    assert custom_key in artifact_ref.uri


def test_response_artifact_custom_key(store: LocalArtifactStore) -> None:
    """Custom artifact key is used when provided."""
    response = httpx.Response(
        status_code=404,
        request=httpx.Request("GET", "https://api.example.com/missing"),
        headers={},
    )

    custom_key = "custom/response/artifact.json"
    artifact_ref = capture_response_artifact(store, response, artifact_key=custom_key)

    assert custom_key in artifact_ref.uri


def test_request_artifact_preserves_method_and_url(store: LocalArtifactStore) -> None:
    """Request method and URL are preserved in artifact."""
    request = httpx.Request(
        method="PUT",
        url="https://api.example.com/users/123",
        headers={},
    )

    artifact_ref = capture_request_artifact(store, request)

    stored_bytes = store.get_bytes(artifact_ref)
    stored_json = stored_bytes.decode("utf-8")

    assert '"method": "PUT"' in stored_json
    assert "https://api.example.com/users/123" in stored_json


def test_response_artifact_preserves_status_code(store: LocalArtifactStore) -> None:
    """Response status code is preserved in artifact."""
    response = httpx.Response(
        status_code=500,
        request=httpx.Request("GET", "https://api.example.com/error"),
        headers={},
    )

    artifact_ref = capture_response_artifact(store, response)

    stored_bytes = store.get_bytes(artifact_ref)
    stored_json = stored_bytes.decode("utf-8")

    assert '"status_code": 500' in stored_json


def test_request_artifact_metadata(store: LocalArtifactStore) -> None:
    """Request artifact includes method and host in metadata."""
    request = httpx.Request(
        method="DELETE",
        url="https://api.example.com/resource",
        headers={},
    )

    artifact_ref = capture_request_artifact(store, request)

    assert artifact_ref.metadata["method"] == "DELETE"
    assert artifact_ref.metadata["host"] == "api.example.com"


def test_response_artifact_metadata(store: LocalArtifactStore) -> None:
    """Response artifact includes status_code, host, and truncation info in metadata."""
    response = httpx.Response(
        status_code=201,
        request=httpx.Request("GET", "https://api.example.com/created"),
        headers={},
        content=b"created",
    )

    artifact_ref = capture_response_artifact(store, response)

    assert artifact_ref.metadata["status_code"] == 201
    assert artifact_ref.metadata["host"] == "api.example.com"
    assert artifact_ref.metadata["truncated"] is False
