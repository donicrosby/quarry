"""Unit tests for IDOR dynamic validation activity.

These tests define the expected behavior for validate_idor_candidate activity.
They should FAIL initially (RED phase) since the validation activity is not yet implemented.
"""

from datetime import UTC, datetime
from unittest.mock import Mock, create_autospec

import httpx
import pytest

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    CandidateFinding,
    Confidence,
    RedactionStatus,
    ValidationResult,
    VulnerabilityClass,
)
from quarry_activities.idor_validation import validate_idor_candidate
from quarry_activities.inputs import ValidateIDORInput


def _make_idor_candidate(
    route: str = "/api/users/{user_id}",
    param_name: str = "user_id",
    auth_hint: str | None = "session_cookie",
) -> CandidateFinding:
    """Create a test IDOR candidate finding."""
    return CandidateFinding(
        id="test-idor-finding",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.IDOR,
        title=f"IDOR in {route}",
        hypothesis="User A can access User B's data by manipulating user_id parameter",
        confidence=Confidence.MEDIUM,
        created_by="test",
        created_at=datetime.now(UTC),
        metadata={
            "route": route,
            "param_name": param_name,
            "auth_hint": auth_hint,
            "user_a_id": "1",
            "user_b_id": "2",
        },
    )


def _make_validate_input(
    candidate: CandidateFinding,
    target_url: str = "http://localhost:8000",
    user_a_creds: tuple[str, str] = ("user-a", "pass-a"),
    user_b_creds: tuple[str, str] = ("user-b", "pass-b"),
) -> ValidateIDORInput:
    """Create a ValidateIDORInput from a candidate."""
    return ValidateIDORInput(
        finding_json=candidate.model_dump_json(),
        target_url=target_url,
        user_a_username=user_a_creds[0],
        user_a_password=user_a_creds[1],
        user_b_username=user_b_creds[0],
        user_b_password=user_b_creds[1],
    )


class TestIDORValidation:
    """Tests for IDOR dynamic validation activity."""

    def test_idor_validated_when_user_a_reads_user_b(
        self,
        mock_http_client: Mock,
        test_candidate: CandidateFinding,
        test_input: ValidateIDORInput,
    ) -> None:
        """When User A can successfully access User B's data, verdict should be 'validated'.

        Mock setup:
        - User A authenticates and gets session
        - User A requests /api/users/2 (User B's ID)
        - Server returns 200 OK with User B's data
        """
        # Mock successful authentication for User A
        auth_response = Mock(spec=httpx.Response)
        auth_response.status_code = 200
        auth_response.cookies = {"session": "user-a-session-token"}

        # Mock successful IDOR exploit - User A accesses User B's data
        idor_response = Mock(spec=httpx.Response)
        idor_response.status_code = 200
        idor_response.json.return_value = {
            "id": "2",
            "name": "User B",
            "email": "user-b@example.com",
        }
        idor_response.request = Mock()
        idor_response.request.url = httpx.URL("http://localhost:8000/api/users/2")
        idor_response.request.method = "GET"
        idor_response.request.headers = httpx.Headers({"Authorization": "Bearer token"})
        idor_response.content = b'{"id": "2", "name": "User B"}'

        mock_http_client.post.return_value = auth_response
        mock_http_client.get.return_value = idor_response

        # Call validation (will fail - function doesn't exist yet)
        result: ValidationResult = validate_idor_candidate(test_input)

        # Assertions
        assert result.verdict == "validated"
        assert result.candidate_finding_id == test_candidate.id
        assert result.scan_id == test_candidate.scan_id
        assert "idor_exploit_successful" in result.checks_run
        assert any("User A accessed User B" in reason for reason in result.reasons)

    def test_idor_inconclusive_when_no_target_url(
        self,
        test_candidate: CandidateFinding,
    ) -> None:
        """When target_url is None, validation should return 'inconclusive'.

        This happens when the scan was run without a target URL.
        The finding should remain a candidate for manual review.
        """
        input_no_target = ValidateIDORInput(
            finding_json=test_candidate.model_dump_json(),
            target_url=None,  # No target to test against
            user_a_username="user-a",
            user_a_password="pass-a",
            user_b_username="user-b",
            user_b_password="pass-b",
        )

        # Call validation (will fail - function doesn't exist yet)
        result: ValidationResult = validate_idor_candidate(input_no_target)

        # Assertions
        assert result.verdict == "inconclusive"
        assert result.candidate_finding_id == test_candidate.id
        assert any("target_url" in reason.lower() for reason in result.reasons)

    def test_idor_inconclusive_when_target_down(
        self,
        mock_http_client: Mock,
        test_input: ValidateIDORInput,
    ) -> None:
        """When target server is unreachable (ConnectionError), verdict should be 'inconclusive'.

        Network failures should not cause validation to fail - they should
        return inconclusive so the finding can be retried later.
        """
        mock_http_client.post.side_effect = httpx.ConnectError("Connection refused")

        # Call validation (will fail - function doesn't exist yet)
        result: ValidationResult = validate_idor_candidate(test_input)

        # Assertions
        assert result.verdict == "inconclusive"
        assert any(
            "connection" in reason.lower() or "unreachable" in reason.lower()
            for reason in result.reasons
        )

    def test_http_artifacts_captured(
        self,
        mock_http_client: Mock,
        test_input: ValidateIDORInput,
        mock_artifact_store: Mock,
    ) -> None:
        """ValidationResult.evidence_refs should contain HTTP_REQUEST and HTTP_RESPONSE artifacts.

        The validation should capture and store:
        - The HTTP request sent (with redacted auth)
        - The HTTP response received
        """
        # Mock successful auth and IDOR response
        auth_response = Mock(spec=httpx.Response)
        auth_response.status_code = 200
        auth_response.cookies = {"session": "user-a-session-token"}

        idor_response = Mock(spec=httpx.Response)
        idor_response.status_code = 200
        idor_response.json.return_value = {"id": "2", "name": "User B"}
        idor_response.request = Mock()
        idor_response.request.url = httpx.URL("http://localhost:8000/api/users/2")
        idor_response.request.method = "GET"
        idor_response.request.headers = httpx.Headers({"Authorization": "Bearer token"})
        idor_response.content = b'{"id": "2"}'

        mock_http_client.post.return_value = auth_response
        mock_http_client.get.return_value = idor_response

        # Mock artifact store to return fake ArtifactRefs
        request_artifact_ref = ArtifactRef(
            id="artifact-req-1",
            uri="file:///tmp/http/requests/get_localhost.json",
            kind=ArtifactKind.HTTP_REQUEST,
            content_type="application/json",
            sha256="abc123",
            size_bytes=256,
            redaction_status=RedactionStatus.REDACTED,
            created_at=datetime.now(UTC),
        )
        response_artifact_ref = ArtifactRef(
            id="artifact-resp-1",
            uri="file:///tmp/http/responses/200_localhost.json",
            kind=ArtifactKind.HTTP_RESPONSE,
            content_type="application/json",
            sha256="def456",
            size_bytes=512,
            redaction_status=RedactionStatus.NOT_REQUIRED,
            created_at=datetime.now(UTC),
        )
        mock_artifact_store.put_json.side_effect = [request_artifact_ref, response_artifact_ref]

        # Call validation (will fail - function doesn't exist yet)
        result: ValidationResult = validate_idor_candidate(
            test_input, artifact_store=mock_artifact_store
        )

        # Assertions
        assert len(result.evidence_refs) >= 2
        artifact_kinds = {ref.kind for ref in result.evidence_refs}
        assert ArtifactKind.HTTP_REQUEST in artifact_kinds
        assert ArtifactKind.HTTP_RESPONSE in artifact_kinds

    def test_auth_credentials_redacted_in_artifacts(
        self,
        mock_http_client: Mock,
        test_input: ValidateIDORInput,
        mock_artifact_store: Mock,
    ) -> None:
        """Authorization header should be 'REDACTED' in stored HTTP_REQUEST artifact.

        Security: credentials must never be stored in plain text.
        """
        # Mock auth response
        auth_response = Mock(spec=httpx.Response)
        auth_response.status_code = 200
        auth_response.cookies = {"session": "user-a-session-token"}

        idor_response = Mock(spec=httpx.Response)
        idor_response.status_code = 200
        idor_response.json.return_value = {"id": "2"}
        idor_response.request = Mock()
        idor_response.request.url = httpx.URL("http://localhost:8000/api/users/2")
        idor_response.request.method = "GET"
        idor_response.request.headers = httpx.Headers({"Authorization": "Bearer user-a:pass-a"})
        idor_response.content = b'{"id": "2"}'

        mock_http_client.post.return_value = auth_response
        mock_http_client.get.return_value = idor_response

        # Mock artifact store to capture what was stored
        captured_request_data: object | None = None

        def capture_put_json(key: str, data: object, **kwargs: object) -> ArtifactRef:
            nonlocal captured_request_data
            if "requests" in key:
                captured_request_data = data
            return ArtifactRef(
                id=f"artifact-{key}",
                uri=f"file:///tmp/{key}",
                kind=ArtifactKind.HTTP_REQUEST,
                content_type="application/json",
                sha256="hash",
                size_bytes=100,
                redaction_status=RedactionStatus.REDACTED,
                created_at=datetime.now(UTC),
            )

        mock_artifact_store.put_json.side_effect = capture_put_json

        # Call validation (will fail - function doesn't exist yet)
        validate_idor_candidate(test_input, artifact_store=mock_artifact_store)

        # Assertions - verify redaction happened
        assert captured_request_data is not None
        request_data = captured_request_data
        if hasattr(request_data, "headers"):
            headers = request_data.headers
        else:
            headers = request_data.get("headers", {})

        # Authorization should be REDACTED, not the actual credentials
        auth_header = headers.get("Authorization")
        assert auth_header == "REDACTED", f"Authorization header was not redacted: {auth_header}"


# Fixtures


@pytest.fixture
def test_candidate() -> CandidateFinding:
    """Create a test IDOR candidate finding."""
    return _make_idor_candidate()


@pytest.fixture
def test_input(test_candidate: CandidateFinding) -> ValidateIDORInput:
    """Create a test ValidateIDORInput."""
    return _make_validate_input(test_candidate)


@pytest.fixture
def mock_http_client() -> Mock:
    """Create a mock httpx.Client."""
    client = create_autospec(httpx.Client, instance=True)
    return client


@pytest.fixture
def mock_artifact_store() -> Mock:
    """Create a mock LocalArtifactStore."""
    store = Mock()
    return store
