"""Startup persona ``profile_ref`` validation (W14, spec "Persona validation at startup").

RED-by-construction: deleting the validation — either the pure predicate or the
workflow-side call that raises before the first scan activity — makes these fail.

The failure this guards is fail-OPEN, not cosmetic: ``dynamic_http`` skips
credential injection when a named profile does not resolve, so a typo'd persona
``profile_ref`` would otherwise dispatch live egress *unauthenticated* under
persona dispatch, with mis-attributed matrix cells and no fail-fast at scan start.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import (
    AuthProfile,
    AuthProfileKind,
    AuthProfileSet,
    PersonaScope,
    TargetAuthorization,
)
from quarry_workflows.roe import ensure_persona_profiles_resolve, persona_profile_errors

REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_SCAN = REPO_ROOT / "src" / "quarry_workflows" / "run_scan.py"

_NOW = datetime(2026, 7, 31, tzinfo=UTC)


def _authz(personas: list[PersonaScope]) -> TargetAuthorization:
    base: dict[str, Any] = {
        "id": "auth-1",
        "target_id": "tgt-1",
        "workspace_id": "local",
        "authorized_by": "secops@example.com",
        "allowed_hosts": ["app.example.com"],
        "allowed_repo_paths": ["/"],
        "created_at": _NOW,
        "personas": personas,
    }
    return TargetAuthorization.model_validate(base)


def _persona(**overrides: Any) -> PersonaScope:
    base: dict[str, Any] = {
        "name": "user",
        "profile_ref": "user-token",
        "allowed_hosts": ["app.example.com"],
        "privilege_level": "user",
    }
    base.update(overrides)
    return PersonaScope.model_validate(base)


def _profile_set(*names: str) -> AuthProfileSet:
    return AuthProfileSet(
        profiles=[AuthProfile(name=n, kind=AuthProfileKind.BEARER) for n in names]
    )


class TestPersonaProfileErrors:
    def test_dangling_ref_is_reported_naming_persona_and_ref(self) -> None:
        authz = _authz([_persona(name="admin", profile_ref="admin-tokenn")])
        errors = persona_profile_errors(authz, _profile_set("admin-token"))
        assert len(errors) == 1
        assert "admin" in errors[0]
        assert "admin-tokenn" in errors[0]

    def test_dangling_ref_with_no_profile_set_is_reported(self) -> None:
        """A scan that loaded no AuthProfileSet cannot resolve any ref → fail."""
        authz = _authz([_persona(profile_ref="user-token")])
        errors = persona_profile_errors(authz, None)
        assert errors and "user-token" in errors[0]

    def test_resolvable_ref_passes(self) -> None:
        authz = _authz([_persona(profile_ref="user-token")])
        assert persona_profile_errors(authz, _profile_set("user-token")) == []

    def test_null_ref_is_the_unauthenticated_persona_and_passes(self) -> None:
        authz = _authz([_persona(name="anon", profile_ref=None, privilege_level="unauthenticated")])
        assert persona_profile_errors(authz, None) == []

    def test_zero_personas_is_a_noop(self) -> None:
        """Backward compatibility: a persona-less authorization never fails here."""
        assert persona_profile_errors(_authz([]), None) == []

    def test_every_dangling_ref_is_reported(self) -> None:
        authz = _authz(
            [
                _persona(name="a", profile_ref="missing-a"),
                _persona(name="b", profile_ref="missing-b"),
                _persona(name="c", profile_ref="present"),
            ]
        )
        errors = persona_profile_errors(authz, _profile_set("present"))
        assert len(errors) == 2
        joined = " ".join(errors)
        assert "missing-a" in joined and "missing-b" in joined


class TestEnsurePersonaProfilesResolve:
    """The fail-closed guard itself — behavioural, so removing the raise fails."""

    def test_dangling_ref_raises_naming_persona_and_ref(self) -> None:
        authz = _authz([_persona(name="admin", profile_ref="admin-tokenn")])
        with pytest.raises(ValueError) as excinfo:
            ensure_persona_profiles_resolve(authz, _profile_set("admin-token"))
        message = str(excinfo.value)
        assert "admin" in message
        assert "admin-tokenn" in message

    def test_no_profile_set_fails_closed(self) -> None:
        """A scan that loaded no AuthProfileSet cannot resolve any ref → fail."""
        authz = _authz([_persona(profile_ref="user-token")])
        with pytest.raises(ValueError):
            ensure_persona_profiles_resolve(authz, None)

    def test_resolvable_and_null_refs_pass(self) -> None:
        authz = _authz(
            [
                _persona(name="user", profile_ref="user-token"),
                _persona(name="anon", profile_ref=None, privilege_level="unauthenticated"),
            ]
        )
        ensure_persona_profiles_resolve(authz, _profile_set("user-token"))

    def test_zero_personas_passes(self) -> None:
        ensure_persona_profiles_resolve(_authz([]), None)


def _run_scan_source() -> str:
    return _RUN_SCAN.read_text(encoding="utf-8")


def _method_source(source: str, name: str) -> str:
    """The source text of class method ``name`` (first match) via the AST."""
    tree = ast.parse(source)
    lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return "\n".join(lines[node.lineno - 1 : node.end_lineno or node.lineno])
    msg = f"method {name!r} not found"
    raise AssertionError(msg)


class TestWorkflowStartupWiring:
    def test_workflow_calls_persona_profile_validation(self) -> None:
        source = _run_scan_source()
        assert "ensure_persona_profiles_resolve(" in source, (
            "the workflow must validate persona profile_refs against the AuthProfileSet"
        )
        assert "persona authorization validation failed" in (
            (REPO_ROOT / "src" / "quarry_workflows" / "roe.py").read_text(encoding="utf-8")
        ), "a dangling persona profile_ref must fail the scan closed with a named error"

    def test_validation_runs_before_the_first_stage_activity(self) -> None:
        """The fail-closed check precedes the CLONE stage — i.e. the first activity."""
        source = _run_scan_source()
        run_body = _method_source(source, "_run")
        validate_at = run_body.index("ensure_persona_profiles_resolve(")
        clone_at = run_body.index("CLONE stage")
        assert validate_at < clone_at, (
            "persona validation must run before any scan activity starts (spec Req 4)"
        )
