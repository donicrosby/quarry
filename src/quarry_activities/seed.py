"""Scan seed utilities.

A seed makes model calls reproducible at temperature=0 for providers that
honour it (forwarded verbatim via LiteLLM). If no seed is pinned in config,
one is derived deterministically from the scan_id UUID so each scan is
independently reproducible without a global pin.
"""

from __future__ import annotations

import uuid as _uuid


def derive_seed(scan_id: str) -> int:
    """Return a deterministic non-negative 31-bit int derived from *scan_id*."""
    return _uuid.UUID(scan_id).int & 0x7FFFFFFF


def resolve_seed(*, pinned: int | None, scan_id: str) -> int:
    """Return *pinned* if set, otherwise derive from *scan_id*."""
    return pinned if pinned is not None else derive_seed(scan_id)
