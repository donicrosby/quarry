"""Tests for multi-persona authorization scope schemas.

``PersonaScope`` binds an ``AuthProfile`` reference to a host+path scope, a
privilege level, and the declared ground truth (``expected_denied_paths``) the
authorization matrix evaluates against. These tests pin the config surface and
its validation: duplicate names, out-of-authorization hosts, and persona scopes
that intersect the top-level ``do_not_test`` ceiling must all be rejected, while
zero personas preserve the historical single-authorization behavior exactly.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from quarry.schemas import PersonaScope, TargetAuthorization


def _authorization(
    *,
    allowed_hosts: list[str] | None = None,
    do_not_test: list[str] | None = None,
    personas: list[PersonaScope] | None = None,
) -> TargetAuthorization:
    return TargetAuthorization(
        id="authz-1",
        target_id="target-1",
        workspace_id="ws-1",
        authorized_by="doni",
        allowed_hosts=allowed_hosts if allowed_hosts is not None else ["app.example.com"],
        allowed_repo_paths=["/srv/app"],
        do_not_test=do_not_test or [],
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        personas=personas or [],
    )


def _persona(**overrides: object) -> PersonaScope:
    base: dict[str, object] = {
        "name": "admin",
        "profile_ref": "admin-token",
        "allowed_hosts": ["app.example.com"],
        "privilege_level": "admin",
    }
    base.update(overrides)
    return PersonaScope(**base)  # type: ignore[arg-type]


class TestPersonaScope:
    def test_defaults(self) -> None:
        persona = _persona()
        assert persona.allowed_paths == ["/"]
        assert persona.do_not_test == []
        assert persona.expected_denied_paths == []
        assert persona.privilege_level == "admin"

    def test_unauthenticated_persona_has_no_profile(self) -> None:
        persona = _persona(name="anon", profile_ref=None, privilege_level="unauthenticated")
        assert persona.profile_ref is None

    def test_round_trip(self) -> None:
        persona = _persona(
            allowed_paths=["/api"],
            do_not_test=["/api/internal/*"],
            expected_denied_paths=["/admin/*"],
        )
        reloaded = PersonaScope.model_validate_json(persona.model_dump_json())
        assert reloaded == persona

    def test_privilege_level_is_required(self) -> None:
        with pytest.raises(ValidationError):
            PersonaScope(name="x", allowed_hosts=["app.example.com"])  # type: ignore[call-arg]

    def test_unknown_privilege_level_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _persona(privilege_level="superuser")

    def test_empty_allowed_hosts_is_accepted_but_matches_nothing(self) -> None:
        # Fail-closed: an empty host list is valid config that matches no request.
        persona = _persona(allowed_hosts=[])
        assert persona.allowed_hosts == []


class TestTargetAuthorizationPersonas:
    def test_zero_personas_is_backward_compatible(self) -> None:
        authz = _authorization()
        assert authz.personas == []
        reloaded = TargetAuthorization.model_validate_json(authz.model_dump_json())
        assert reloaded.personas == []

    def test_valid_persona_accepted(self) -> None:
        authz = _authorization(personas=[_persona()])
        assert [p.name for p in authz.personas] == ["admin"]

    def test_personas_round_trip(self) -> None:
        authz = _authorization(
            personas=[
                _persona(name="anon", profile_ref=None, privilege_level="unauthenticated"),
                _persona(name="user", profile_ref="user-token", privilege_level="user"),
            ]
        )
        reloaded = TargetAuthorization.model_validate_json(authz.model_dump_json())
        assert [p.name for p in reloaded.personas] == ["anon", "user"]
        assert reloaded.personas[0].profile_ref is None

    def test_duplicate_persona_names_rejected(self) -> None:
        with pytest.raises(ValidationError, match="duplicate persona name"):
            _authorization(
                personas=[
                    _persona(name="dup", profile_ref="a"),
                    _persona(name="dup", profile_ref="b"),
                ]
            )

    def test_persona_host_outside_top_level_rejected(self) -> None:
        with pytest.raises(ValidationError, match="absent from the top-level"):
            _authorization(
                allowed_hosts=["app.example.com"],
                personas=[_persona(allowed_hosts=["other.example.com"])],
            )

    def test_persona_allowed_path_intersecting_do_not_test_rejected(self) -> None:
        with pytest.raises(ValidationError, match="intersects"):
            _authorization(
                do_not_test=["/admin/*"],
                personas=[_persona(allowed_paths=["/admin/users"])],
            )

    def test_persona_expected_denied_path_intersecting_do_not_test_rejected(self) -> None:
        with pytest.raises(ValidationError, match="intersects"):
            _authorization(
                do_not_test=["/billing"],
                personas=[_persona(expected_denied_paths=["/billing"])],
            )

    def test_persona_scope_matching_exact_do_not_test_prefix_rejected(self) -> None:
        # ``_path_matches`` convention: a bare pattern blocks the path and its subtree.
        with pytest.raises(ValidationError, match="intersects"):
            _authorization(
                do_not_test=["/internal"],
                personas=[_persona(allowed_paths=["/internal/secrets"])],
            )

    def test_persona_scope_outside_do_not_test_accepted(self) -> None:
        authz = _authorization(
            do_not_test=["/admin/*"],
            personas=[_persona(allowed_paths=["/public"], expected_denied_paths=["/private/*"])],
        )
        assert authz.personas[0].allowed_paths == ["/public"]
