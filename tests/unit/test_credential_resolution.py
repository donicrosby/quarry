"""Tests for credential resolution (ADR-018 §7): resolve_credentials().

Written RED first — these fail until credentials.py exists.

Key invariants:
- resolve_credentials() raises when a required SecretRef.env is unset.
- Agent sees only profile name, never the resolved value.
- Resolved value is registered in the Scrubber denylist before send.
- Login POST host must be within allowed_hosts; rejected otherwise.
- bearer/basic/static_header/cookie kinds are resolved purely from env.
- login_flow makes a POST; resolved token is injected into subsequent headers.
- No resolved secret ever persists to a ToolCallRecord or AgentStep.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from quarry.schemas import (
    AuthProfile,
    AuthProfileKind,
    CredentialExtract,
    LoginStep,
    SecretRef,
)
from quarry_activities.credentials import (
    CachedCredential,
    CredentialCache,
    resolve_credentials,
)
from quarry_models.redaction import Scrubber

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bearer_profile(name: str = "user1", env: str = "QUARRY_SECRET_USER1_TOKEN") -> AuthProfile:
    return AuthProfile(
        name=name,
        kind=AuthProfileKind.BEARER,
        secret_ref=SecretRef(env=env),
    )


def _basic_profile(
    name: str = "basic-user",
    username_env: str = "QUARRY_SECRET_BASIC_USER",
    password_env: str = "QUARRY_SECRET_BASIC_PASS",
) -> AuthProfile:
    return AuthProfile(
        name=name,
        kind=AuthProfileKind.BASIC,
        username=username_env,  # username can be non-secret; secret_ref holds the password
        secret_ref=SecretRef(env=password_env),
    )


_UNUSED_BASIC_PROFILE = _basic_profile  # referenced in future basic-auth tests


# ---------------------------------------------------------------------------
# bearer kind
# ---------------------------------------------------------------------------


class TestResolveBearerProfile:
    def test_bearer_reads_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("QUARRY_SECRET_USER1_TOKEN", "tok_live_abc123")
        profile = _bearer_profile()
        scrubber = Scrubber()
        cache = CredentialCache(scan_id="s1")
        cred = resolve_credentials(
            profile=profile,
            cache=cache,
            scrubber=scrubber,
            allowed_hosts=("localhost",),
        )
        assert cred is not None
        assert cred.header_name == "Authorization"
        assert cred.header_value == "Bearer tok_live_abc123"

    def test_bearer_registers_value_in_scrubber(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("QUARRY_SECRET_USER1_TOKEN", "tok_MUST_BE_SCRUBBED")
        profile = _bearer_profile()
        scrubber = Scrubber()
        cache = CredentialCache(scan_id="s2")
        resolve_credentials(
            profile=profile,
            cache=cache,
            scrubber=scrubber,
            allowed_hosts=("localhost",),
        )
        result = scrubber.scrub("response contains tok_MUST_BE_SCRUBBED here")
        assert "tok_MUST_BE_SCRUBBED" not in result.text

    def test_bearer_raises_on_missing_env(self) -> None:
        profile = _bearer_profile(env="QUARRY_SECRET_NONEXISTENT_XYZ_9999")
        scrubber = Scrubber()
        cache = CredentialCache(scan_id="s3")
        with pytest.raises(EnvironmentError, match="QUARRY_SECRET_NONEXISTENT_XYZ_9999"):
            resolve_credentials(
                profile=profile,
                cache=cache,
                scrubber=scrubber,
                allowed_hosts=("localhost",),
            )


class TestResolveCacheHit:
    def test_cache_hit_skips_env_lookup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A cache hit should return the cached credential without re-reading env."""
        profile = _bearer_profile()
        scrubber = Scrubber()
        cache = CredentialCache(scan_id="s4")
        cached = CachedCredential(
            profile_name="user1",
            header_name="Authorization",
            header_value="Bearer cached_value",
        )
        cache.put(cached)

        # No env var set — proves we're using the cache, not reading env
        cred = resolve_credentials(
            profile=profile,
            cache=cache,
            scrubber=scrubber,
            allowed_hosts=("localhost",),
        )
        assert cred is not None
        assert cred.header_value == "Bearer cached_value"


class TestResolveStaticHeader:
    def test_static_header_uses_name_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("QUARRY_SECRET_API_KEY", "key_abc")
        profile = AuthProfile(
            name="api-key",
            kind=AuthProfileKind.STATIC_HEADER,
            secret_ref=SecretRef(env="QUARRY_SECRET_API_KEY"),
            name_hint="X-Api-Key",
        )
        scrubber = Scrubber()
        cache = CredentialCache(scan_id="s5")
        cred = resolve_credentials(
            profile=profile,
            cache=cache,
            scrubber=scrubber,
            allowed_hosts=("localhost",),
        )
        assert cred is not None
        assert cred.header_name == "X-Api-Key"
        assert cred.header_value == "key_abc"


class TestResolveLoginFlow:
    def test_login_flow_host_must_be_in_allowed_hosts(self) -> None:
        """A login POST to a host outside allowed_hosts is rejected."""
        profile = AuthProfile(
            name="login-flow",
            kind=AuthProfileKind.LOGIN_FLOW,
            login=LoginStep(
                path="/auth/login",
                field_template={"username": "admin", "password": "${secret:QUARRY_SECRET_PASS}"},
                extract=CredentialExtract(from_json="$.access_token", inject_as="bearer"),
            ),
        )
        scrubber = Scrubber()
        cache = CredentialCache(scan_id="s6")
        with pytest.raises((ValueError, Exception), match="[Aa]llowed|[Ss]cope|[Hh]ost"):
            resolve_credentials(
                profile=profile,
                cache=cache,
                scrubber=scrubber,
                allowed_hosts=("other-host.com",),
                target_host="localhost",  # login endpoint host is localhost, not in allowed_hosts
            )

    def test_login_flow_performs_post_and_extracts_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QUARRY_SECRET_PASS", "supersecret")
        profile = AuthProfile(
            name="login-flow",
            kind=AuthProfileKind.LOGIN_FLOW,
            login=LoginStep(
                path="/auth/login",
                field_template={"username": "admin", "password": "${secret:QUARRY_SECRET_PASS}"},
                extract=CredentialExtract(from_json="$.access_token", inject_as="bearer"),
                ttl_seconds=3600,
            ),
        )
        scrubber = Scrubber()
        cache = CredentialCache(scan_id="s7")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "jwt_tok_xyz"}
        mock_response.text = '{"access_token": "jwt_tok_xyz"}'

        with patch("quarry_activities.credentials.httpx") as mock_httpx:
            mock_client = MagicMock()
            mock_httpx.Client.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_httpx.Client.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response

            cred = resolve_credentials(
                profile=profile,
                cache=cache,
                scrubber=scrubber,
                allowed_hosts=("localhost",),
                target_host="localhost",
                target_port=9000,
            )

        assert cred is not None
        assert cred.header_value == "Bearer jwt_tok_xyz"

    def test_login_flow_extracted_token_is_scrubber_registered(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QUARRY_SECRET_PASS2", "secret2")
        profile = AuthProfile(
            name="login-scrub",
            kind=AuthProfileKind.LOGIN_FLOW,
            login=LoginStep(
                path="/auth/login",
                field_template={"password": "${secret:QUARRY_SECRET_PASS2}"},
                extract=CredentialExtract(from_json="$.token", inject_as="bearer"),
            ),
        )
        scrubber = Scrubber()
        cache = CredentialCache(scan_id="s8")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"token": "EXTRACTED_SECRET_TOKEN_ABC"}
        mock_response.text = '{"token": "EXTRACTED_SECRET_TOKEN_ABC"}'

        with patch("quarry_activities.credentials.httpx") as mock_httpx:
            mock_client = MagicMock()
            mock_httpx.Client.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_httpx.Client.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response

            resolve_credentials(
                profile=profile,
                cache=cache,
                scrubber=scrubber,
                allowed_hosts=("localhost",),
                target_host="localhost",
                target_port=9000,
            )

        result = scrubber.scrub("token is EXTRACTED_SECRET_TOKEN_ABC in body")
        assert "EXTRACTED_SECRET_TOKEN_ABC" not in result.text
