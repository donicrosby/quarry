"""Tests for Trace persistence (ADR-022 §Trace persistence).

Written RED first — these fail until:
- QuarryRepository gains save_trace / load_traces
- persist-scan-state gains "save_trace" / "load_traces" dispatch cases

Trace records were previously discarded entirely (no save_trace existed), so
the reachability verdict and severity re-ranking never survived resume. See
openspec/changes/iterative-coverage-loop/design.md.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from quarry.schemas import (
    ReachabilityVerdict,
    Scan,
    ScanStatus,
    Target,
    Trace,
    local_scan_profile,
)
from quarry_activities.inputs import PersistScanStateInput
from quarry_activities.repo import persist_scan_state
from quarry_persistence import QuarryRepository


def _make_scan_and_target(scan_id: str, tmp_path: Path) -> tuple[Scan, Target]:
    now = datetime.now(UTC)
    target = Target(
        id=f"{scan_id}-target",
        workspace_id="local",
        repo_path=str(tmp_path),
        created_at=now,
    )
    scan = Scan(
        id=scan_id,
        workspace_id="local",
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.RUNNING,
        created_at=now,
    )
    return scan, target


class TestRepositoryTracePersistence:
    def test_save_and_load_trace_round_trip(self, tmp_path: Path) -> None:
        repository = QuarryRepository(tmp_path / "quarry.db")
        scan, target = _make_scan_and_target("scan-trace-1", tmp_path)
        repository.create_scan(scan, target)

        trace = Trace(
            id="trace-1",
            scan_id=scan.id,
            finding_id="finding-1",
            reachable=ReachabilityVerdict.REACHABLE,
        )
        repository.save_trace(trace)

        loaded = repository.load_traces(scan.id)
        assert len(loaded) == 1
        assert loaded[0].id == "trace-1"
        assert loaded[0].finding_id == "finding-1"
        assert loaded[0].reachable == ReachabilityVerdict.REACHABLE

    def test_load_traces_scoped_to_scan(self, tmp_path: Path) -> None:
        repository = QuarryRepository(tmp_path / "quarry.db")
        scan_a, target_a = _make_scan_and_target("scan-trace-a", tmp_path)
        scan_b, target_b = _make_scan_and_target("scan-trace-b", tmp_path)
        repository.create_scan(scan_a, target_a)
        repository.create_scan(scan_b, target_b)

        repository.save_trace(
            Trace(
                id="trace-a",
                scan_id=scan_a.id,
                finding_id="f-a",
                reachable=ReachabilityVerdict.REACHABLE,
            )
        )
        repository.save_trace(
            Trace(
                id="trace-b",
                scan_id=scan_b.id,
                finding_id="f-b",
                reachable=ReachabilityVerdict.NOT_REACHABLE,
            )
        )

        loaded_a = repository.load_traces(scan_a.id)
        assert len(loaded_a) == 1
        assert loaded_a[0].id == "trace-a"

    def test_save_trace_is_idempotent_on_retry(self, tmp_path: Path) -> None:
        """Re-saving the same trace id (activity retry) must not create a duplicate."""
        repository = QuarryRepository(tmp_path / "quarry.db")
        scan, target = _make_scan_and_target("scan-trace-retry", tmp_path)
        repository.create_scan(scan, target)

        trace = Trace(
            id="trace-retry-1",
            scan_id=scan.id,
            finding_id="finding-1",
            reachable=ReachabilityVerdict.INDETERMINATE,
        )
        repository.save_trace(trace)
        repository.save_trace(trace)

        loaded = repository.load_traces(scan.id)
        assert len(loaded) == 1


class TestPersistScanStateDispatch:
    def test_save_trace_dispatch(self, tmp_path: Path) -> None:
        db_path = tmp_path / "quarry.db"
        repository = QuarryRepository(db_path)
        scan, target = _make_scan_and_target("scan-dispatch-1", tmp_path)
        repository.create_scan(scan, target)

        trace = Trace(
            id="trace-dispatch-1",
            scan_id=scan.id,
            finding_id="finding-1",
            reachable=ReachabilityVerdict.REACHABLE,
        )
        persist_scan_state(
            PersistScanStateInput(
                db_path=str(db_path),
                operation="save_trace",
                payload_json=json.dumps({"trace": json.loads(trace.model_dump_json())}),
            )
        )

        loaded = repository.load_traces(scan.id)
        assert len(loaded) == 1
        assert loaded[0].id == "trace-dispatch-1"

    def test_load_traces_dispatch(self, tmp_path: Path) -> None:
        db_path = tmp_path / "quarry.db"
        repository = QuarryRepository(db_path)
        scan, target = _make_scan_and_target("scan-dispatch-2", tmp_path)
        repository.create_scan(scan, target)
        repository.save_trace(
            Trace(
                id="trace-dispatch-2",
                scan_id=scan.id,
                finding_id="finding-2",
                reachable=ReachabilityVerdict.NOT_REACHABLE,
            )
        )

        result = persist_scan_state(
            PersistScanStateInput(
                db_path=str(db_path),
                operation="load_traces",
                payload_json=json.dumps({"scan_id": scan.id}),
            )
        )

        assert isinstance(result, list)
        result_list = cast("list[dict[str, Any]]", result)
        assert len(result_list) == 1
        assert result_list[0]["id"] == "trace-dispatch-2"
