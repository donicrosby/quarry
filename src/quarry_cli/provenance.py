"""quarry provenance verify — evidence-grade prompt provenance verification.

Provides:
- ``verify_invocation``: checks that a stored ModelInvocation's hash fields
  match expected values.  Called by the ``quarry provenance verify`` CLI command
  and by retention/GC inspection.
- ``should_gc_scan``: returns False for legal_hold=True scans (GC exemption).

See ADR-019 (prompt provenance addendum).
"""

from __future__ import annotations

from hashlib import sha256
from typing import TYPE_CHECKING

from quarry.schemas import ModelInvocation, Scan

if TYPE_CHECKING:
    from quarry_artifacts.store import ArtifactStore


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


def verify_stored_prompt(invocation: ModelInvocation, store: ArtifactStore) -> bool | None:
    """Verify a stored MODEL_PROMPT artifact against the invocation's hashes.

    Reads the bytes referenced by ``invocation.prompt_ref``, re-splits the
    messages, strips the system message's provenance header, and confirms:

    - re-hashing the system body reproduces ``invocation.system_prompt_hash``, and
    - the stored header's ``template_sha256`` matches ``invocation.template_sha256``.

    Returns ``None`` when the invocation has no ``prompt_ref`` (nothing to check),
    ``True`` when the stored bytes match the record, and ``False`` on any mismatch
    (a tampered or drifted artifact).
    """
    from quarry_artifacts.store import decode_prompt_messages
    from quarry_prompts.build_prompt import strip_provenance_header

    if invocation.prompt_ref is None:
        return None

    messages = decode_prompt_messages(store.get_bytes(invocation.prompt_ref))
    system_content = next((m.content for m in messages if m.role == "system"), None)
    if system_content is None:
        return False

    header, body = strip_provenance_header(system_content)
    if (
        invocation.system_prompt_hash
        and sha256(body.encode("utf-8")).hexdigest() != invocation.system_prompt_hash
    ):
        return False
    return not (
        invocation.template_sha256 and header.get("template_sha256") != invocation.template_sha256
    )


def should_gc_scan(scan: Scan) -> bool:
    """Return True when the scan is eligible for GC/retention sweep.

    Scans with ``legal_hold=True`` must never be purged — they are exempt from
    the GC retention sweep regardless of age or status.
    """
    return not scan.legal_hold
