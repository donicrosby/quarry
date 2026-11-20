"""Rules-of-engagement enforcement for the live-exploitation track (design D4).

Pure, replay-safe predicates that turn the previously-dead ``TargetAuthorization``
fields into enforced controls. Exploiting a live target is the highest-blast-radius
capability in the roadmap, so scope is fail-closed: an empty allowlist blocks all,
an unset/expired authorization permits nothing, and ``do_not_test`` paths are refused
before any egress.
"""

from __future__ import annotations

from datetime import datetime
from fnmatch import fnmatch

from quarry.schemas import AuthProfileSet, PersonaScope, TargetAuthorization


def authorization_active(
    authorization: TargetAuthorization | None, *, now: datetime | None = None
) -> bool:
    """True only when a live authorization exists, names an authorizer, and is unexpired.

    Fail-closed: ``None`` or a blank ``authorized_by`` permits nothing. Expiry is only
    enforced when both ``expires_at`` and ``now`` are known; callers pass ``workflow.now()``.
    """
    if authorization is None or not authorization.authorized_by.strip():
        return False
    return not (
        authorization.expires_at is not None and now is not None and now >= authorization.expires_at
    )


def request_in_scope(authorization: TargetAuthorization, *, host: str, path: str) -> bool:
    """True only when the target host is allow-listed and the path is not do-not-test.

    Fail-closed: an empty ``allowed_hosts`` blocks every request. ``do_not_test``
    entries are matched as globs (e.g. ``/admin/*``) or exact paths.
    """
    if host not in authorization.allowed_hosts:
        return False
    return all(not _path_matches(path, pattern) for pattern in authorization.do_not_test)


def repo_path_in_scope(authorization: TargetAuthorization, repo_path: str) -> bool:
    """True when ``repo_path`` falls under one of the authorized ``allowed_repo_paths``."""
    for allowed in authorization.allowed_repo_paths:
        prefix = allowed.rstrip("/")
        if repo_path == prefix or repo_path.startswith(prefix + "/"):
            return True
    return False


def _path_matches(path: str, pattern: str) -> bool:
    """Match a request path against a do-not-test pattern (glob or exact/prefix)."""
    if fnmatch(path, pattern):
        return True
    prefix = pattern.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def persona_for_request(
    authorization: TargetAuthorization, *, host: str, path: str
) -> PersonaScope | None:
    """The first persona whose scope covers (*host*, *path*), or ``None``.

    Pure predicate beside :func:`request_in_scope` (D4 precedent). A persona
    matches when the host is in its ``allowed_hosts``, the path falls under one
    of its ``allowed_paths``, and the path is not blocked by its own
    ``do_not_test``. The first match in declaration order wins.

    Fail-closed: an empty ``allowed_hosts`` (or ``allowed_paths``) matches
    nothing. Top-level ``do_not_test`` is enforced by :func:`request_in_scope`;
    persona selection refines that ceiling and never widens it.
    """
    for persona in authorization.personas:
        if host not in persona.allowed_hosts:
            continue
        if not any(_path_matches(path, allowed) for allowed in persona.allowed_paths):
            continue
        if any(_path_matches(path, blocked) for blocked in persona.do_not_test):
            continue
        return persona
    return None


def persona_profile_errors(
    authorization: TargetAuthorization,
    auth_profile_set: AuthProfileSet | None,
) -> list[str]:
    """Return one message per persona whose non-null ``profile_ref`` is dangling.

    Fail-closed startup validation (spec "Persona validation at startup"): every
    persona's non-null ``profile_ref`` must resolve to a name in the scan's
    ``AuthProfileSet`` before any scan activity starts. A dangling reference is a
    hard error — dispatching it would otherwise reach ``dynamic_http``, which
    skips credential injection for an unresolved profile and sends the request
    *unauthenticated*. ``None`` refs are the declared unauthenticated persona and
    always pass. An empty return list means every reference resolves.

    Pure and workflow-side: the caller decides how to fail (the workflow raises
    before its first activity).
    """
    errors: list[str] = []
    for persona in authorization.personas:
        if persona.profile_ref is None:
            continue
        if auth_profile_set is None or auth_profile_set.get(persona.profile_ref) is None:
            errors.append(
                f"persona '{persona.name}' profile_ref '{persona.profile_ref}' "
                "does not resolve in the AuthProfileSet"
            )
    return errors


def ensure_persona_profiles_resolve(
    authorization: TargetAuthorization,
    auth_profile_set: AuthProfileSet | None,
) -> None:
    """Fail-closed startup guard: raise naming every dangling persona ``profile_ref``.

    Called at the top of ``RunScanWorkflow._run``, before the first scan activity.
    Raising here is the security-relevant part: proceeding would let
    ``dynamic_http`` skip credential injection for the unresolved profile and send
    the request **unauthenticated**, with no fail-fast at scan start.
    """
    errors = persona_profile_errors(authorization, auth_profile_set)
    if errors:
        msg = "persona authorization validation failed: " + "; ".join(errors)
        raise ValueError(msg)
