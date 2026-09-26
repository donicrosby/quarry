"""ADR-017 safety-guard coverage for the dynamic_validate stage.

These tests lock in the fail-closed authorization model for the NEW
``dynamic_validate`` role using the REAL tool registry (so the role gate, the
``allowed_hosts`` allow-list, scope exclusions / ``block_dynamic``, and the
auth-profile guard all apply to live probes the dynamic-validation agent might
attempt).  They complement the generic ToolRunner guard tests by asserting the
guarantees hold specifically for the dynamic_validate seat and that credentials
are never rendered into the dynamic-validation prompt.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from quarry.schemas import (
    AuthProfile,
    AuthProfileKind,
    AuthProfileSet,
    CandidateFinding,
    Confidence,
    ScopeExclusion,
    SecretRef,
    Severity,
    VulnerabilityClass,
)
from quarry_tools.registry import load_registry
from quarry_tools.runner import ToolCallRecord, ToolRunner

_NOW = datetime(2026, 6, 11, tzinfo=UTC)


def _runner(
    tmp_path: Path,
    *,
    allowed_hosts: list[str] | None = None,
    scope_exclusions: list[ScopeExclusion] | None = None,
    auth_profile_set: AuthProfileSet | None = None,
) -> ToolRunner:
    return ToolRunner(
        repo_root=tmp_path,
        role="dynamic_validate",
        registry=load_registry(),
        allowed_hosts=allowed_hosts,
        scope_exclusions=scope_exclusions,
        auth_profile_set=auth_profile_set,
    )


# ---------------------------------------------------------------------------
# 3.1 allowed_hosts fail-closed (dynamic_validate role, real http_request tool)
# ---------------------------------------------------------------------------


class TestAllowedHostsFailClosed:
    def test_http_request_permitted_for_dynamic_validate_role(self, tmp_path: Path) -> None:
        """The role gate must allow http_request in the dynamic_validate seat."""
        assert "dynamic_validate" in load_registry()["http_request"].roles

    def test_empty_allowlist_blocks_all_http_requests(self, tmp_path: Path) -> None:
        runner = _runner(tmp_path, allowed_hosts=[])
        record = runner.run("http_request", {"method": "GET", "path": "/users/1"})
        assert record.allowed is False
        assert record.status == "refused"
        assert record.denied_reason is not None

    def test_out_of_scope_host_refused_before_io(self, tmp_path: Path) -> None:
        runner = _runner(tmp_path, allowed_hosts=["localhost"])
        record = runner.run(
            "http_request",
            {"method": "GET", "path": "/steal", "host": "attacker.io"},
        )
        assert record.allowed is False
        assert record.status == "refused"
        assert record.denied_reason is not None
        # No response was captured — refusal happened before any I/O.
        assert record.output is None or "attacker.io" not in str(record.output)

    def test_refused_record_is_never_dropped(self, tmp_path: Path) -> None:
        runner = _runner(tmp_path, allowed_hosts=[])
        record = runner.run("http_request", {"method": "POST", "path": "/anything"})
        assert isinstance(record, ToolCallRecord)
        assert record.allowed is False

    def test_in_scope_host_allowed(self, tmp_path: Path) -> None:
        runner = _runner(tmp_path, allowed_hosts=["localhost"])
        record = runner.run(
            "http_request",
            {"method": "GET", "path": "/users/1", "host": "localhost"},
        )
        assert record.allowed is True


# ---------------------------------------------------------------------------
# 3.2 scope exclusions + block_dynamic + auth-profile guard + no creds in prompt
# ---------------------------------------------------------------------------


class TestScopeExclusionsAndCredentials:
    def test_block_dynamic_exclusion_refuses_matching_route(self, tmp_path: Path) -> None:
        exc = ScopeExclusion(
            kind="route", value="GET /admin/*", reason="out of scope", block_dynamic=True
        )
        runner = _runner(tmp_path, allowed_hosts=["localhost"], scope_exclusions=[exc])
        record = runner.run(
            "http_request",
            {"method": "GET", "path": "/admin/users", "host": "localhost"},
        )
        assert record.allowed is False
        assert record.status == "refused"
        assert record.denied_reason is not None

    def test_non_block_dynamic_exclusion_does_not_refuse(self, tmp_path: Path) -> None:
        exc = ScopeExclusion(
            kind="route", value="GET /admin/*", reason="doc-only", block_dynamic=False
        )
        runner = _runner(tmp_path, allowed_hosts=["localhost"], scope_exclusions=[exc])
        record = runner.run(
            "http_request",
            {"method": "GET", "path": "/admin/users", "host": "localhost"},
        )
        assert record.allowed is True

    def test_unknown_auth_profile_is_refused(self, tmp_path: Path) -> None:
        auth_set = AuthProfileSet(
            profiles=[
                AuthProfile(
                    name="session",
                    kind=AuthProfileKind.BEARER,
                    secret_ref=SecretRef(env="QUARRY_SECRET_TOKEN"),
                )
            ]
        )
        runner = _runner(tmp_path, allowed_hosts=["localhost"], auth_profile_set=auth_set)
        record = runner.run(
            "http_request",
            {"method": "GET", "path": "/users/2", "host": "localhost", "auth_profile": "forged"},
        )
        assert record.allowed is False
        assert record.status == "refused"
        assert record.denied_reason is not None

    def test_known_auth_profile_passes_guard(self, tmp_path: Path) -> None:
        auth_set = AuthProfileSet(
            profiles=[
                AuthProfile(
                    name="session",
                    kind=AuthProfileKind.BEARER,
                    secret_ref=SecretRef(env="QUARRY_SECRET_TOKEN"),
                )
            ]
        )
        runner = _runner(tmp_path, allowed_hosts=["localhost"], auth_profile_set=auth_set)
        record = runner.run(
            "http_request",
            {"method": "GET", "path": "/users/2", "host": "localhost", "auth_profile": "session"},
        )
        assert record.allowed is True

    def test_credentials_never_rendered_into_dynamic_validate_prompt(
        self, tmp_path: Path, monkeypatch: object
    ) -> None:
        """The dynamic-validation seed prompt must never contain a secret value.

        Credentials are injected worker-side at dispatch (CredentialCache); the
        agent only ever sees an auth_profile NAME.  Even with a live secret in the
        environment, the persisted seed prompt carries no secret value.
        """
        import os

        from quarry_activities.dynamic_validate import (
            DynamicValidateResponse,
            dynamic_validate_impl,
        )
        from quarry_models.mock_client import MockModelClient

        secret_value = "s3cr3t-live-token-VALUE"
        os.environ["QUARRY_SECRET_TOKEN"] = secret_value
        try:
            finding = CandidateFinding(
                id="cf-dyn-cred",
                scan_id="scan-cred",
                workspace_id="ws-1",
                vuln_class=VulnerabilityClass.IDOR,
                title="IDOR on /users/{id}",
                hypothesis="Unauth read of another user's profile via GET /users/{id}.",
                affected_component="src/routes/users.py:42",
                root_cause_key="idor-users-id",
                confidence=Confidence.HIGH,
                severity=Severity.HIGH,
                created_by="hunt-agent",
                created_at=_NOW,
            )
            client = MockModelClient(
                default=DynamicValidateResponse(
                    verdict="corroborated",
                    reasons=["users.py:42 no owner check"],
                    proposed_http_specs=[
                        {"method": "GET", "path": "/users/2", "auth_profile": "session"}
                    ],
                )
            )
            artifact_root = tmp_path / "artifacts"
            artifact_root.mkdir()

            dynamic_validate_impl(
                finding=finding,
                repo_path=str(tmp_path),
                client=client,
                max_iterations=3,
                allowed_hosts=("localhost",),
                artifact_root=str(artifact_root),
            )

            # No persisted artifact under the seed-prompt root may contain the secret.
            for path in artifact_root.rglob("*"):
                if path.is_file():
                    assert secret_value not in path.read_text(encoding="utf-8", errors="ignore")
        finally:
            os.environ.pop("QUARRY_SECRET_TOKEN", None)
