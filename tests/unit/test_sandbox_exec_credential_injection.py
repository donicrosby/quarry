"""Tests for _resolve_credentials in sandbox_exec_activity (US-005).

Written RED first -- these fail until _resolve_credentials is implemented.

Safety invariants:
- _resolve_credentials returns QUARRY_INJECTED_CRED_<PROFILE> env vars for each profile.
- The env var value is the raw secret so the scrubber catches bare leakage in stdout/stderr.
- Profiles with no secret_ref resolve to nothing (no env var emitted).
- None auth_profile_set_json returns {}.
"""

from __future__ import annotations

import pytest


class TestResolveCredentials:
    """_resolve_credentials resolves AuthProfileSet profiles to QUARRY_INJECTED_CRED_* env vars."""

    def test_bearer_profile_returns_token_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A bearer profile resolves to QUARRY_INJECTED_CRED_<NAME> with the raw token value."""
        monkeypatch.setenv("US005_BEARER_TOKEN", "my-secret-bearer-token")

        from quarry.schemas import AuthProfile, AuthProfileKind, AuthProfileSet, SecretRef
        from quarry_activities.sandbox_exec import (
            _resolve_credentials,  # type: ignore[reportPrivateUsage]
        )

        profile = AuthProfile(
            name="token",
            kind=AuthProfileKind.BEARER,
            secret_ref=SecretRef(env="US005_BEARER_TOKEN"),
        )
        auth_set = AuthProfileSet(profiles=[profile])

        result = _resolve_credentials(auth_set.model_dump_json())

        assert "QUARRY_INJECTED_CRED_TOKEN" in result
        assert "my-secret-bearer-token" in result["QUARRY_INJECTED_CRED_TOKEN"]

    def test_none_json_returns_empty(self) -> None:
        """None auth_profile_set_json must return an empty dict (unauthenticated scan)."""
        from quarry_activities.sandbox_exec import (
            _resolve_credentials,  # type: ignore[reportPrivateUsage]
        )

        result = _resolve_credentials(None)

        assert result == {}

    def test_profile_name_uppercased_in_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Profile name is uppercased and hyphens replaced with underscores for the env var key."""
        monkeypatch.setenv("US005_APIKEY_TOKEN", "api-key-value-xyz")

        from quarry.schemas import AuthProfile, AuthProfileKind, AuthProfileSet, SecretRef
        from quarry_activities.sandbox_exec import (
            _resolve_credentials,  # type: ignore[reportPrivateUsage]
        )

        profile = AuthProfile(
            name="api-key",
            kind=AuthProfileKind.BEARER,
            secret_ref=SecretRef(env="US005_APIKEY_TOKEN"),
        )
        auth_set = AuthProfileSet(profiles=[profile])

        result = _resolve_credentials(auth_set.model_dump_json())

        assert "QUARRY_INJECTED_CRED_API_KEY" in result

    def test_scrubber_registered_via_build_scrubber_with_creds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Values returned by _resolve_credentials are registered in the Scrubber."""
        monkeypatch.setenv("US005_SCRUB_TOKEN", "scrub-this-secret-value")

        from quarry.schemas import AuthProfile, AuthProfileKind, AuthProfileSet, SecretRef
        from quarry_activities.sandbox_exec import (
            _resolve_credentials,  # type: ignore[reportPrivateUsage]
            build_scrubber_with_creds,
        )

        profile = AuthProfile(
            name="admin",
            kind=AuthProfileKind.BEARER,
            secret_ref=SecretRef(env="US005_SCRUB_TOKEN"),
        )
        auth_set = AuthProfileSet(profiles=[profile])

        resolved = _resolve_credentials(auth_set.model_dump_json())
        scrubber = build_scrubber_with_creds(resolved)
        result = scrubber.scrub("output: scrub-this-secret-value found in stdout")

        assert "scrub-this-secret-value" not in result.text
        assert result.hits > 0
