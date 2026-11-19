"""GC retention helpers for quarry_cli.

sweep_scans partitions a list of Scan objects into GC-eligible and retained
sets.  Delegates all hold-exemption logic to should_gc_scan so policy stays
in one place.

execute_gc reclaims storage for eligible scans via QuarryRepository.delete_scan.

Quarantine (D6 / proof-artifact-quarantine): a scan still holding unreleased
quarantined proof artifacts is retained, not reclaimed — quarantined artifacts
survive a retention sweep until an operator releases them.  The caller supplies
the per-scan proof artifacts it knows about; the exemption decision itself stays
in ``quarantine.sweep_retains_artifact``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from quarry.schemas import ProofArtifact, Scan
from quarry_artifacts.quarantine import sweep_retains_artifact
from quarry_cli.provenance import should_gc_scan


class ScanDataStore(Protocol):
    """The only repository capability the retention sweep needs.

    ``QuarryRepository`` satisfies it structurally, and tests can supply a light
    double instead of a real SQLite database.
    """

    def delete_scan(self, scan_id: str) -> None: ...


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


def retains_quarantined_artifacts(
    scan_id: str,
    quarantined_artifacts: Mapping[str, Sequence[ProofArtifact]] | None,
) -> bool:
    """True when *scan_id* still holds an unreleased quarantined artifact.

    Pure policy check: consults ``quarantine.sweep_retains_artifact`` for each
    artifact the caller supplied, so the sweep exemption rule lives in one place.
    """
    if not quarantined_artifacts:
        return False
    return any(
        sweep_retains_artifact(artifact) for artifact in quarantined_artifacts.get(scan_id, ())
    )


def execute_gc(
    eligible: list[Scan],
    repo: ScanDataStore,
    *,
    quarantined_artifacts: Mapping[str, Sequence[ProofArtifact]] | None = None,
) -> list[str]:
    """Reclaim storage for eligible scans. Returns IDs of reclaimed scans.

    Idempotent: already-deleted scans produce no error and are still counted.
    Safety valve: legal_hold=True scans in the input list are silently skipped.
    Quarantined artifacts are exempt: a scan with unreleased quarantined proof
    artifacts is retained (only release or operator deletion removes them).
    """
    reclaimed: list[str] = []
    for scan in eligible:
        if scan.legal_hold:
            continue
        if retains_quarantined_artifacts(scan.id, quarantined_artifacts):
            continue
        repo.delete_scan(scan.id)
        reclaimed.append(scan.id)
    return reclaimed
