"""W14 persona schema tests (Group 1: PersonaScope + TargetAuthorization.personas).

Locks in the persona-declaration contract: a persona binds an auth profile to a
host+path scope with a privilege level and declared ground truth
(``expected_denied_paths``); zero personas preserve the historical
single-authorization behavior exactly; and a persona can never escape the
top-level authorization (host allowlist, do-not-test ceiling).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from quarry.schemas import PersonaScope, TargetAuthorization

_NOW = datetime(2026, 7, 31, tzinfo=UTC)


def _authz(**overrides: Any) -> TargetAuthorization:
    base: dict[str, Any] = {
        "id": "auth-1",
        "target_id": "tgt-1",
        "workspace_id": "local",
        "authorized_by": "secops@example.com",
        "allowed_hosts": ["localhost"],
        "allowed_repo_paths": ["/"],
        "created_at": _NOW,
    }
    base.update(overrides)
    return TargetAuthorization.model_validate(base)


def _persona(**overrides: Any) -> PersonaScope:
    base: dict[str, Any] = {
        "name": "admin",
        "profile_ref": "admin-profile",
        "allowed_hosts": ["localhost"],
        "privilege_level": "admin",
    }
    base.update(overrides)
    return PersonaScope.model_validate(base)


class TestPersonaScope:
    def test_valid_persona_round_trips(self) -> None:
        persona = _persona(
            allowed_paths=["/admin"],
            do_not_test=["/admin/health"],
            expected_denied_paths=["/admin/users"],
        )
        dumped = persona.model_dump_json()
        restored = PersonaScope.model_validate_json(dumped)
        assert restored == persona

    def test_allowed_paths_defaults_to_root(self) -> None:
        assert _persona().allowed_paths == ["/"]

    def test_unauthenticated_persona_allows_null_profile_ref(self) -> None:
        persona = _persona(name="anon", profile_ref=None, privilege_level="unauthenticated")
        assert persona.profile_ref is None

    def test_invalid_privilege_level_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _persona(privilege_level="root")


class TestTargetAuthorizationPersonas:
    def test_zero_personas_preserves_backward_compatibility(self) -> None:
        authz = _authz()
        assert authz.personas == []

    def test_persona_with_valid_profile_and_scope_is_accepted(self) -> None:
        authz = _authz(personas=[_persona()])
        assert len(authz.personas) == 1
        assert authz.personas[0].name == "admin"

    def test_duplicate_persona_names_rejected(self) -> None:
        with pytest.raises(ValidationError, match="duplicate persona name"):
            _authz(personas=[_persona(name="user"), _persona(name="user")])

    def test_persona_host_outside_top_level_rejected(self) -> None:
        with pytest.raises(ValidationError, match="absent from the top-level allowed_hosts"):
            _authz(personas=[_persona(allowed_hosts=["evil.example"])])

    def test_persona_allowed_path_intersecting_do_not_test_rejected(self) -> None:
        with pytest.raises(ValidationError, match="intersects top-level do_not_test"):
            _authz(
                do_not_test=["/admin/*"],
                personas=[_persona(allowed_paths=["/admin/secrets"])],
            )

    def test_persona_expected_denied_path_intersecting_do_not_test_rejected(self) -> None:
        with pytest.raises(ValidationError, match="intersects top-level do_not_test"):
            _authz(
                do_not_test=["/billing"],
                personas=[_persona(expected_denied_paths=["/billing"])],
            )

    def test_persona_root_scope_does_not_conflict_with_narrow_do_not_test(self) -> None:
        # The default allowed_paths ["/"] must not be read as intersecting a
        # narrow do_not_test pattern — dispatch still refuses those paths.
        authz = _authz(do_not_test=["/admin/*"], personas=[_persona()])
        assert authz.personas[0].allowed_paths == ["/"]
