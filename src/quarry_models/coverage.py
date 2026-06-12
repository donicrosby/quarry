"""Coverage floor enforcement (ADR-021).

Pure model-layer logic: no Temporal, no I/O. The Temporal activity
(quarry_activities/coverage.py) handles the database-side ledger.

The coverage floor is a correctness invariant: every vuln_class in the
operator's focused set must have at least min_per_class tasks per scan.
This is checked in Python after model output — it is NOT delegated to the
prompt.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from quarry.schemas import AgentTask, VulnerabilityClass


def enforce_coverage_floor(
    tasks: list[AgentTask],
    vuln_classes: list[VulnerabilityClass],
    min_per_class: int = 2,
) -> list[AgentTask]:
    """Return tasks with synthetic gapfill tasks appended for any shortfall.

    Iterates only *vuln_classes* (the operator's focused set, i.e.
    ``ScanProfile.vuln_classes``). Classes not in the focused set are ignored.

    For each focused class that has fewer than *min_per_class* existing tasks,
    appends synthetic ``AgentTask(source="gapfill", ...)`` entries whose
    ``task_prompt`` includes "no findings here yet" and the vuln_class name, as
    required by the spec.

    The original tasks appear first; synthetic tasks are appended.
    """
    if not vuln_classes:
        return list(tasks)

    # Count existing tasks per focused class
    counts: dict[VulnerabilityClass, int] = {vc: 0 for vc in vuln_classes}
    for task in tasks:
        if task.vuln_class is not None and task.vuln_class in counts:
            counts[task.vuln_class] += 1

    result = list(tasks)
    now = datetime.now(UTC)

    for vc in vuln_classes:
        shortfall = min_per_class - counts[vc]
        for _ in range(shortfall):
            nudge = (
                f"No findings here yet for {vc.value}. "
                f"Please look specifically for {vc.value} vulnerabilities "
                f"in the scoped area. There are no findings here yet — "
                f"search the codebase thoroughly for {vc.value} patterns."
            )
            result.append(
                AgentTask(
                    id=str(uuid.uuid4()),
                    scan_id="",
                    role="hunt",
                    task_name=f"gapfill-{vc.value}",
                    task_prompt=nudge,
                    vuln_class=vc,
                    scope=None,
                    source="gapfill",
                    status="pending",
                    created_at=now,
                )
            )

    return result
