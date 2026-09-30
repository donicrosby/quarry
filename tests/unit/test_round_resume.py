"""Round-scoped resume tests (ADR-D3, cruft-purge 2.2).

Contract: a workflow that crashes in round >= 1 resumes from the persisted
round cursor with the persisted task queue — it does not restart the loop,
re-derive tasks from the ArchitectureDoc, or duplicate candidates.
"""

from __future__ import annotations

from quarry_workflows.run_scan import (  # pyright: ignore[reportPrivateUsage]
    LOOP_DONE,
    _round_cursor_from_stage,
)


def test_round_cursor_from_stage_round0_is_none() -> None:
    """A round-0-only stage marker must not advance the loop cursor."""
    assert _round_cursor_from_stage("HUNT") == 0
    assert _round_cursor_from_stage("AGENTIC_VALIDATE") == 0
    assert _round_cursor_from_stage("DEDUP") == 0
    assert _round_cursor_from_stage(None) == 0


def test_round_cursor_from_round_markers() -> None:
    """Round-scoped markers 'ROUND:<n>:<STAGE>' decode to the completed round."""
    assert _round_cursor_from_stage("ROUND:0:TRACER") == 0
    assert _round_cursor_from_stage("ROUND:1:TRACER") == 1
    assert _round_cursor_from_stage("ROUND:2:PROVE") == 2


def test_round_cursor_loop_terminal_markers() -> None:
    """Post-loop stages imply the loop finished: cursor = max rounds seen."""
    # COVERAGE/REPORT imply the loop ran to its stop; resume must skip it.
    # The max round index is unknowable from the marker alone, so these map
    # to the sentinel that tells the caller "loop is done".
    assert _round_cursor_from_stage("COVERAGE") == LOOP_DONE
    assert _round_cursor_from_stage("REPORT") == LOOP_DONE
    assert _round_cursor_from_stage("COMPLETED") == LOOP_DONE
