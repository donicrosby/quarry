"""Persist model-invocation cost/usage provenance produced by an agentic activity.

Agentic activities (hunt/validate/gapfill/dedup/recon) drive a model client whose
``invocations`` list accumulates one ``ModelInvocation`` per model call, carrying
token counts and best-effort USD cost. This helper writes those rows to the scan
database so the report can render a "Cost & usage" section and the workflow can
track cumulative spend for the per-stage budget.

The agent loop stamps a placeholder ``scan_id`` ("loop") on each request, so we
overwrite it with the real scan id at persist time — that is the key the rows are
loaded back by.
"""

from __future__ import annotations

from typing import Any


def persist_model_invocations(db_path: str | None, scan_id: str, client: Any) -> int:
    """Save a client's recorded ``ModelInvocation`` rows to the scan DB.

    Returns the number of rows persisted. No-op (returns 0) when *db_path* is
    falsy or the client recorded nothing — so mock-backed unit tests that pass no
    db_path are unaffected.
    """
    if not db_path:
        return 0
    invocations = getattr(client, "invocations", None)
    if not invocations:
        return 0

    from quarry_persistence import QuarryRepository

    repository = QuarryRepository(db_path)
    count = 0
    for inv in invocations:
        repository.save_model_invocation(inv.model_copy(update={"scan_id": scan_id}))
        count += 1
    return count
