"""Planted missing-authz helper (regression fixture).

Exposes internal admin state to any caller with no authentication or
authorization check on the caller identity.
"""

_INTERNAL_STATE = {"users": "42", "uptime_hours": "1337"}


def admin_status(user: str) -> dict[str, str]:
    # No check that `user` is an administrator.
    return {"requested_by": user, **_INTERNAL_STATE}
