"""Unit tests for quarry_cli/retention.py - sweep_scans and execute_gc."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

from quarry.schemas import Scan, ScanProfile, ScanStatus, Target, VulnerabilityClass

_NOW = datetime(2026, 6, 12, tzinfo=UTC)


def _make_scan(scan_id: str = "s-1", legal_hold: bool = False) -> Scan:
    return Scan(
        id=scan_id,
        workspace_id="ws-1",
        target_id="t-1",
        requested_by="u@e.com",
        profile=ScanProfile(
            id="p-1",
            name="test",
            vuln_classes=[VulnerabilityClass.COMMAND_INJECTION],
        ),
        status=ScanStatus.COMPLETED,
        created_at=_NOW,
        legal_hold=legal_hold,
    )


class TestSweepScansImportable:
    def test_sweep_scans_importable(self) -> None:
        from quarry_cli.retention import sweep_scans

        assert callable(sweep_scans)

    def test_sweep_scans_delegates_to_should_gc_scan(self) -> None:
        import inspect

        import quarry_cli.retention as m

        src = inspect.getsource(m)
        assert "should_gc_scan" in src
        assert "from quarry_cli.provenance import" in src or "quarry_cli.provenance" in src


class TestSweepScansPartitioning:
    def test_legal_hold_scan_in_retained_not_eligible(self) -> None:
        from quarry_cli.retention import sweep_scans

        held = _make_scan("held-1", legal_hold=True)
        free = _make_scan("free-1", legal_hold=False)
        eligible, retained = sweep_scans([held, free])
        assert "held-1" in [s.id for s in retained]
        assert "held-1" not in [s.id for s in eligible]

    def test_normal_scan_appears_in_eligible(self) -> None:
        from quarry_cli.retention import sweep_scans

        free = _make_scan("free-2", legal_hold=False)
        eligible, _ = sweep_scans([free])
        assert any(s.id == "free-2" for s in eligible)

    def test_empty_input_returns_empty_tuples(self) -> None:
        from quarry_cli.retention import sweep_scans

        eligible, retained = sweep_scans([])
        assert eligible == [] and retained == []

    def test_all_held_returns_empty_eligible(self) -> None:
        from quarry_cli.retention import sweep_scans

        scans = [_make_scan("held-" + str(i), legal_hold=True) for i in range(3)]
        eligible, retained = sweep_scans(scans)
        assert eligible == [] and len(retained) == 3

    def test_all_free_returns_empty_retained(self) -> None:
        from quarry_cli.retention import sweep_scans

        scans = [_make_scan("free-" + str(i), legal_hold=False) for i in range(3)]
        eligible, retained = sweep_scans(scans)
        assert len(eligible) == 3 and retained == []

    def test_mixed_list_partitioned_correctly(self) -> None:
        from quarry_cli.retention import sweep_scans

        scans = [
            _make_scan("h1", True),
            _make_scan("f1", False),
            _make_scan("h2", True),
            _make_scan("f2", False),
        ]
        eligible, retained = sweep_scans(scans)
        assert {s.id for s in eligible} == {"f1", "f2"}
        assert {s.id for s in retained} == {"h1", "h2"}

    def test_no_scan_in_both_partitions(self) -> None:
        from quarry_cli.retention import sweep_scans

        eligible, retained = sweep_scans([_make_scan("h1", True), _make_scan("f1", False)])
        assert {s.id for s in eligible}.isdisjoint({s.id for s in retained})

    def test_sweep_scans_is_deterministic(self) -> None:
        from quarry_cli.retention import sweep_scans

        scans = [_make_scan("h1", True), _make_scan("f1", False), _make_scan("f2", False)]
        r1 = sweep_scans(scans)
        r2 = sweep_scans(scans)
        assert [s.id for s in r1[0]] == [s.id for s in r2[0]]
        assert [s.id for s in r1[1]] == [s.id for s in r2[1]]


def _make_target(scan_id: str) -> Target:
    return Target(
        id=f"t-{scan_id}",
        workspace_id="ws-1",
        repo_path="/tmp/repo",
        created_at=_NOW,
    )


class TestExecuteGcImportable:
    def test_execute_gc_importable(self) -> None:
        from quarry_cli.retention import execute_gc

        assert callable(execute_gc)


class TestExecuteGcBehavior:
    def test_calls_delete_for_each_eligible_scan(self) -> None:
        from quarry_cli.retention import execute_gc
        from quarry_persistence import QuarryRepository

        eligible = [_make_scan("s-1"), _make_scan("s-2")]
        repo = MagicMock(spec=QuarryRepository)

        reclaimed = execute_gc(eligible, repo)

        assert repo.delete_scan.call_count == 2
        assert set(reclaimed) == {"s-1", "s-2"}

    def test_returns_reclaimed_ids(self) -> None:
        from quarry_cli.retention import execute_gc
        from quarry_persistence import QuarryRepository

        eligible = [_make_scan("s-abc")]
        repo = MagicMock(spec=QuarryRepository)

        reclaimed = execute_gc(eligible, repo)

        assert reclaimed == ["s-abc"]

    def test_idempotent_no_double_delete_error(self, tmp_path: Path) -> None:
        from quarry_cli.retention import execute_gc
        from quarry_persistence import QuarryRepository

        repo = QuarryRepository(tmp_path / "q.db")
        scan = _make_scan("s-gc-1")
        target = _make_target("s-gc-1")
        repo.create_scan(scan, target)

        ids_first = execute_gc([scan], repo)
        ids_second = execute_gc([scan], repo)

        assert ids_first == ["s-gc-1"]
        assert ids_second == ["s-gc-1"]

    def test_skips_legal_hold_scan(self) -> None:
        from quarry_cli.retention import execute_gc
        from quarry_persistence import QuarryRepository

        held = _make_scan("h-1", legal_hold=True)
        repo = MagicMock(spec=QuarryRepository)

        reclaimed = execute_gc([held], repo)

        repo.delete_scan.assert_not_called()
        assert reclaimed == []

    def test_mixed_list_skips_held_deletes_free(self) -> None:
        from quarry_cli.retention import execute_gc
        from quarry_persistence import QuarryRepository

        eligible = [_make_scan("f-1"), _make_scan("h-1", legal_hold=True), _make_scan("f-2")]
        repo = MagicMock(spec=QuarryRepository)

        reclaimed = execute_gc(eligible, repo)

        assert repo.delete_scan.call_count == 2
        assert set(reclaimed) == {"f-1", "f-2"}
        assert "h-1" not in reclaimed
