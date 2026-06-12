"""quarry provenance verify — evidence-grade prompt provenance verification.

Provides:
- ``verify_invocation``: checks that a stored ModelInvocation's hash fields
  match expected values.  Called by the ``quarry provenance verify`` CLI command
  and by retention/GC inspection.
- ``should_gc_scan``: returns False for legal_hold=True scans (GC exemption).

See ADR-019 (prompt provenance addendum).
"""

from __future__ import annotations

from quarry.schemas import ModelInvocation, Scan


def verify_invocation(
    invocation: ModelInvocation,
    *,
    expected_system_hash: str | None = None,
    expected_template_sha256: str | None = None,
    expected_user_prompt_hash: str | None = None,
) -> bool:
    """Verify a stored ModelInvocation's per-part hashes against expected values.

    Returns ``True`` when all provided expected hashes match the persisted fields.
    Returns ``False`` when any provided hash does not match (tampered record).

    Only the hashes explicitly passed as kwargs are checked; others are skipped.
    This allows callers to check just the system-prompt hash, just the template
    SHA, or a full set of hashes.

    Example::

        ok = verify_invocation(inv, expected_system_hash=recomputed_hash)
        if not ok:
            raise ValueError(f"Provenance mismatch for invocation {inv.id}")
    """
    if expected_system_hash is not None and invocation.system_prompt_hash != expected_system_hash:
        return False
    if (
        expected_template_sha256 is not None
        and invocation.template_sha256 != expected_template_sha256
    ):
        return False
    return not (
        expected_user_prompt_hash is not None
        and invocation.user_prompt_hash != expected_user_prompt_hash
    )


def should_gc_scan(scan: Scan) -> bool:
    """Return True when the scan is eligible for GC/retention sweep.

    Scans with ``legal_hold=True`` must never be purged — they are exempt from
    the GC retention sweep regardless of age or status.
    """
    return not scan.legal_hold
