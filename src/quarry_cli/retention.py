"""GC retention helpers for quarry_cli.

sweep_scans partitions a list of Scan objects into GC-eligible and retained
sets.  Delegates all hold-exemption logic to should_gc_scan so policy stays
in one place.

execute_gc reclaims storage for eligible scans via QuarryRepository.delete_scan.
"""

from __future__ import annotations

from quarry.schemas import Scan
from quarry_cli.provenance import should_gc_scan
from quarry_persistence import QuarryRepository


def sweep_scans(scans: list[Scan]) -> tuple[list[Scan], list[Scan]]:
    """Partition scans into (eligible, retained).

    eligible  - scans that may be reclaimed by GC (legal_hold=False)
    retained  - scans that must not be touched (legal_hold=True)

    Pure function: no I/O, no side effects, deterministic.
    """
    eligible: list[Scan] = []
    retained: list[Scan] = []
    for scan in scans:
        if should_gc_scan(scan):
            eligible.append(scan)
        else:
            retained.append(scan)
    return eligible, retained


def execute_gc(eligible: list[Scan], repo: QuarryRepository) -> list[str]:
    """Reclaim storage for eligible scans. Returns IDs of reclaimed scans.

    Idempotent: already-deleted scans produce no error and are still counted.
    Safety valve: legal_hold=True scans in the input list are silently skipped.
    """
    reclaimed: list[str] = []
    for scan in eligible:
        if scan.legal_hold:
            continue
        repo.delete_scan(scan.id)
        reclaimed.append(scan.id)
    return reclaimed
