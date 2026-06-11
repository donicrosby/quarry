"""Tests for target authentication schemas (ADR-018).

Written RED first — these fail until SecretRef, TotpConfig, CredentialExtract,
LoginStep, AuthProfileKind, AuthProfile, and AuthProfileSet are added to
src/quarry/schemas.py.

Key invariant: no inline secret may appear anywhere in an AuthProfile.
The _CREDENTIAL_RE validator pattern must fire on auth_profile fields just as
it does on HttpRequestSpec.auth_profile.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from quarry.schemas import (
    AuthProfile,
    AuthProfileKind,
    AuthProfileSet,
    CredentialExtract,
    LoginStep,
    SecretRef,
    TotpConfig,
)


class TestSecretRef:
    def test_round_trip(self) -> None:
        ref = SecretRef(env="QUARRY_SECRET_ADMIN_TOKEN")
        reloaded = SecretRef.model_validate_json(ref.model_dump_json())
        assert reloaded.env == "QUARRY_SECRET_ADMIN_TOKEN"

    def test_env_var_name_required(self) -> None:
        with pytest.raises(ValidationError):
            SecretRef(env="")

    def test_accepts_any_nonempty_env_name(self) -> None:
        ref = SecretRef(env="MY_TOKEN")
        assert ref.env == "MY_TOKEN"


class TestTotpConfig:
    def test_defaults(self) -> None:
        cfg = TotpConfig(seed_ref=SecretRef(env="QUARRY_SECRET_TOTP_SEED"))
        assert cfg.digits == 6
        assert cfg.period_seconds == 30
        assert cfg.algorithm == "SHA1"

    def test_custom_config(self) -> None:
        cfg = TotpConfig(
            seed_ref=SecretRef(env="QUARRY_SECRET_TOTP_SEED"),
            digits=8,
            period_seconds=60,
            algorithm="SHA256",
        )
        assert cfg.digits == 8
        assert cfg.period_seconds == 60
        assert cfg.algorithm == "SHA256"

    def test_round_trip(self) -> None:
        cfg = TotpConfig(seed_ref=SecretRef(env="QUARRY_SECRET_TOTP_SEED"))
        reloaded = TotpConfig.model_validate_json(cfg.model_dump_json())
        assert reloaded.seed_ref.env == "QUARRY_SECRET_TOTP_SEED"


class TestCredentialExtract:
    def test_json_path(self) -> None:
        ce = CredentialExtract(from_json="$.access_token", inject_as="bearer")
        assert ce.from_json == "$.access_token"
        assert ce.inject_as == "bearer"

    def test_cookie_extract(self) -> None:
        ce = CredentialExtract(from_cookie="session", inject_as="cookie")
        assert ce.from_cookie == "session"

    def test_header_extract(self) -> None:
        ce = CredentialExtract(from_header="X-Auth-Token", inject_as="bearer")
        assert ce.from_header == "X-Auth-Token"

    def test_round_trip(self) -> None:
        ce = CredentialExtract(from_json="$.token", inject_as="bearer")
        reloaded = CredentialExtract.model_validate_json(ce.model_dump_json())
        assert reloaded.from_json == "$.token"


class TestLoginStep:
    def test_minimal(self) -> None:
        step = LoginStep(
            path="/api/login",
            field_template={
                "username": "${username}",
                "password": "${secret:QUARRY_SECRET_PASSWORD}",
            },
            extract=CredentialExtract(from_json="$.token", inject_as="bearer"),
        )
        assert step.path == "/api/login"
        assert step.ttl_seconds is None

    def test_with_ttl(self) -> None:
        step = LoginStep(
            path="/auth",
            field_template={"pass": "${secret:QUARRY_SECRET_PASS}"},
            extract=CredentialExtract(from_json="$.access_token", inject_as="bearer"),
            ttl_seconds=3600,
        )
        assert step.ttl_seconds == 3600

    def test_round_trip(self) -> None:
        step = LoginStep(
            path="/login",
            field_template={"pw": "${secret:QUARRY_SECRET_PW}"},
            extract=CredentialExtract(from_json="$.tok", inject_as="bearer"),
        )
        reloaded = LoginStep.model_validate_json(step.model_dump_json())
        assert reloaded.path == "/login"


class TestAuthProfileKind:
    def test_all_kinds_exist(self) -> None:
        kinds = {k.value for k in AuthProfileKind}
        assert kinds >= {"bearer", "basic", "static_header", "cookie", "login_flow"}


class TestAuthProfile:
    def test_bearer_profile(self) -> None:
        profile = AuthProfile(
            name="api_key",
            kind=AuthProfileKind.BEARER,
            secret_ref=SecretRef(env="QUARRY_SECRET_API_KEY"),
        )
        assert profile.name == "api_key"
        assert profile.kind == AuthProfileKind.BEARER
        assert profile.secret_ref is not None
        assert profile.secret_ref.env == "QUARRY_SECRET_API_KEY"
        assert profile.login is None
        assert profile.totp is None

    def test_basic_profile(self) -> None:
        profile = AuthProfile(
            name="basic_user",
            kind=AuthProfileKind.BASIC,
            username="admin",
            secret_ref=SecretRef(env="QUARRY_SECRET_BASIC_PW"),
        )
        assert profile.username == "admin"

    def test_static_header_profile(self) -> None:
        profile = AuthProfile(
            name="api_header",
            kind=AuthProfileKind.STATIC_HEADER,
            secret_ref=SecretRef(env="QUARRY_SECRET_HEADER_VAL"),
            name_hint="X-Api-Key",
        )
        assert profile.name_hint == "X-Api-Key"

    def test_cookie_profile(self) -> None:
        profile = AuthProfile(
            name="session_cookie",
            kind=AuthProfileKind.COOKIE,
            secret_ref=SecretRef(env="QUARRY_SECRET_COOKIE"),
            name_hint="session",
        )
        assert profile.name_hint == "session"

    def test_login_flow_profile(self) -> None:
        profile = AuthProfile(
            name="login_user",
            kind=AuthProfileKind.LOGIN_FLOW,
            login=LoginStep(
                path="/api/auth/login",
                field_template={
                    "email": "${username}",
                    "password": "${secret:QUARRY_SECRET_PASSWORD}",
                },
                extract=CredentialExtract(from_json="$.token", inject_as="bearer"),
                ttl_seconds=1800,
            ),
        )
        assert profile.login is not None
        assert profile.login.path == "/api/auth/login"

    def test_login_flow_with_totp(self) -> None:
        profile = AuthProfile(
            name="otp_user",
            kind=AuthProfileKind.LOGIN_FLOW,
            login=LoginStep(
                path="/auth",
                field_template={
                    "pass": "${secret:QUARRY_SECRET_PASS}",
                    "otp": "${totp}",
                },
                extract=CredentialExtract(from_json="$.access_token", inject_as="bearer"),
            ),
            totp=TotpConfig(seed_ref=SecretRef(env="QUARRY_SECRET_TOTP_SEED")),
        )
        assert profile.totp is not None
        assert profile.totp.seed_ref.env == "QUARRY_SECRET_TOTP_SEED"

    def test_inline_secret_rejected_in_secret_ref_env(self) -> None:
        """An env var name that looks like an inline token must be rejected."""
        with pytest.raises(ValidationError, match="inline"):
            AuthProfile(
                name="bad_profile",
                kind=AuthProfileKind.BEARER,
                # env value looks like a real token — must be rejected
                secret_ref=SecretRef(env="sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"),
            )

    def test_round_trip(self) -> None:
        profile = AuthProfile(
            name="api_key",
            kind=AuthProfileKind.BEARER,
            secret_ref=SecretRef(env="QUARRY_SECRET_API_KEY"),
        )
        reloaded = AuthProfile.model_validate_json(profile.model_dump_json())
        assert reloaded.name == "api_key"
        assert reloaded.kind == AuthProfileKind.BEARER


class TestAuthProfileSet:
    def test_empty(self) -> None:
        ps = AuthProfileSet(profiles=[])
        assert ps.profiles == []

    def test_lookup_by_name(self) -> None:
        profiles = [
            AuthProfile(
                name="api_key",
                kind=AuthProfileKind.BEARER,
                secret_ref=SecretRef(env="QUARRY_SECRET_API_KEY"),
            ),
            AuthProfile(
                name="admin",
                kind=AuthProfileKind.BASIC,
                username="admin",
                secret_ref=SecretRef(env="QUARRY_SECRET_ADMIN_PW"),
            ),
        ]
        ps = AuthProfileSet(profiles=profiles)
        found = ps.get("api_key")
        assert found is not None
        assert found.name == "api_key"
        assert ps.get("nonexistent") is None

    def test_round_trip(self) -> None:
        ps = AuthProfileSet(
            profiles=[
                AuthProfile(
                    name="tok",
                    kind=AuthProfileKind.BEARER,
                    secret_ref=SecretRef(env="QUARRY_SECRET_TOK"),
                )
            ]
        )
        reloaded = AuthProfileSet.model_validate_json(ps.model_dump_json())
        assert reloaded.profiles[0].name == "tok"

    def test_duplicate_names_rejected(self) -> None:
        """Profile names must be unique within a set."""
        with pytest.raises(ValidationError, match="duplicate"):
            AuthProfileSet(
                profiles=[
                    AuthProfile(
                        name="dup",
                        kind=AuthProfileKind.BEARER,
                        secret_ref=SecretRef(env="QUARRY_SECRET_A"),
                    ),
                    AuthProfile(
                        name="dup",
                        kind=AuthProfileKind.BEARER,
                        secret_ref=SecretRef(env="QUARRY_SECRET_B"),
                    ),
                ]
            )
