"""W14 persona dispatch predicate tests (Group 2: roe.persona_for_request).

Persona selection is workflow-side and pure. It refines ``request_in_scope``
(never widens it): the first persona whose host+path scope covers the request
wins; per-persona do-not-test narrows further; an empty host/path scope matches
nothing (fail-closed).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from quarry.schemas import PersonaScope, TargetAuthorization
from quarry_workflows.roe import persona_for_request

_NOW = datetime(2026, 7, 31, tzinfo=UTC)


def _authz(personas: list[PersonaScope]) -> TargetAuthorization:
    base: dict[str, Any] = {
        "id": "auth-1",
        "target_id": "tgt-1",
        "workspace_id": "local",
        "authorized_by": "secops@example.com",
        "allowed_hosts": ["localhost"],
        "allowed_repo_paths": ["/"],
        "created_at": _NOW,
        "personas": personas,
    }
    return TargetAuthorization.model_validate(base)


def _persona(**overrides: Any) -> PersonaScope:
    base: dict[str, Any] = {
        "name": "user",
        "profile_ref": "user-profile",
        "allowed_hosts": ["localhost"],
        "privilege_level": "user",
    }
    base.update(overrides)
    return PersonaScope.model_validate(base)


class TestPersonaForRequest:
    def test_selects_persona_for_matching_host_and_path(self) -> None:
        authz = _authz([_persona(name="admin", allowed_paths=["/admin"])])
        selected = persona_for_request(authz, host="localhost", path="/admin/users")
        assert selected is not None
        assert selected.name == "admin"

    def test_returns_none_when_host_not_covered(self) -> None:
        authz = _authz([_persona()])
        assert persona_for_request(authz, host="other.example", path="/x") is None

    def test_returns_none_when_path_outside_allowed_paths(self) -> None:
        authz = _authz([_persona(allowed_paths=["/admin"])])
        assert persona_for_request(authz, host="localhost", path="/users/1") is None

    def test_returns_none_when_persona_do_not_test_blocks_path(self) -> None:
        authz = _authz([_persona(do_not_test=["/admin/health"])])
        assert persona_for_request(authz, host="localhost", path="/admin/health") is None

    def test_first_matching_persona_wins_on_overlap(self) -> None:
        first = _persona(name="first", allowed_paths=["/"])
        second = _persona(name="second", allowed_paths=["/"])
        authz = _authz([first, second])
        selected = persona_for_request(authz, host="localhost", path="/anything")
        assert selected is not None
        assert selected.name == "first"

    def test_empty_allowed_hosts_matches_nothing(self) -> None:
        authz = _authz([_persona(allowed_hosts=[])])
        assert persona_for_request(authz, host="localhost", path="/x") is None

    def test_no_personas_returns_none(self) -> None:
        authz = _authz([])
        assert persona_for_request(authz, host="localhost", path="/x") is None
