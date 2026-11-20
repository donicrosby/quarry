"""``quarry traffic`` — inspect, export, snapshot, and reclaim capture stores.

Operator surface for the recording-proxy funnel:

* ``query``    — read the capture index (by host, template, status, hunt task,
  or canary flag);
* ``export``   — write a portable host-scoped archive before reclamation;
* ``snapshot`` — bind capture blobs to a finding in the evidence store;
* ``reclaim``  — delete unreferenced capture blobs once the store exceeds the
  configured threshold (``QUARRY_TRAFFIC_CAPTURE_MAX_BYTES``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from quarry.config import QuarrySettings
from quarry_traffic.capture_index import CaptureIndex, CaptureRow, capture_index_path
from quarry_traffic.capture_store import CaptureStore
from quarry_traffic.evidence import EvidenceStore

traffic_app = typer.Typer(help="Recording-proxy capture and evidence store.")


def _settings() -> QuarrySettings:
    return QuarrySettings()


def _open_index(settings: QuarrySettings) -> CaptureIndex:
    return CaptureIndex(capture_index_path(settings.traffic_capture_root))


def _open_evidence(settings: QuarrySettings, store: CaptureStore) -> EvidenceStore:
    return EvidenceStore(settings.evidence_store_root, capture=store)


@traffic_app.command("query")
def query(
    host: Annotated[str | None, typer.Option("--host", help="Target host (netloc)")] = None,
    url_template: Annotated[
        str | None, typer.Option("--url-template", help="Normalized URL template")
    ] = None,
    status_code: Annotated[int | None, typer.Option("--status-code")] = None,
    hunt_task_id: Annotated[str | None, typer.Option("--hunt-task-id")] = None,
    canary: Annotated[bool, typer.Option("--canary", help="Only canary-callback rows")] = False,
    since: Annotated[
        str | None, typer.Option("--since", help="ISO-8601 lower bound (with --until)")
    ] = None,
    until: Annotated[
        str | None, typer.Option("--until", help="ISO-8601 upper bound (with --since)")
    ] = None,
) -> None:
    """Query the capture index and print matching exchanges."""
    settings = _settings()
    store = CaptureStore(settings.traffic_capture_root)
    index = _open_index(settings)
    try:
        if host is not None:
            rows = index.by_host(host)
        elif url_template is not None:
            rows = index.by_url_template(url_template)
        elif status_code is not None:
            rows = index.by_status_code(status_code)
        elif hunt_task_id is not None:
            rows = index.by_hunt_task_id(hunt_task_id)
        elif canary:
            rows = index.by_canary_callback()
        elif since is not None and until is not None:
            rows = index.by_time_range(since, until)
        else:
            rows = index.rows()
    finally:
        index.close()

    for row in rows:
        typer.echo(_format_row(row, blob_present=_blob_present(store, row)))
    typer.echo(f"{len(rows)} row(s)")


def _blob_present(store: CaptureStore, row: CaptureRow) -> bool:
    return row.sha256 is not None and store.has_blob(row.sha256)


def _format_row(row: CaptureRow, *, blob_present: bool) -> str:
    status = "-" if row.status_code is None else str(row.status_code)
    digest = row.sha256 or "-"
    blob = "blob=present" if blob_present else "blob=-"
    canary = "canary=true" if row.canary_callback else "canary=false"
    hunt = row.hunt_task_id or "-"
    return "\t".join(
        [row.timestamp, row.method, status, row.host, row.url_template, digest, blob, canary, hunt]
    )


@traffic_app.command("export")
def export(
    host: Annotated[str, typer.Argument(help="Target host (netloc) to export")],
    dest: Annotated[
        Path | None, typer.Option("--dest", help="Directory for the portable archive")
    ] = None,
) -> None:
    """Write a portable archive of one host's exchanges and blobs."""
    settings = _settings()
    store = CaptureStore(settings.traffic_capture_root)
    index = _open_index(settings)
    try:
        archive = store.export_host(index, host, dest)
    finally:
        index.close()
    typer.echo(str(archive))


@traffic_app.command("snapshot")
def snapshot(
    finding_id: Annotated[str, typer.Option("--finding-id", help="Finding to bind evidence to")],
    sha: Annotated[list[str], typer.Option("--sha", help="Capture blob digest (repeatable)")],
) -> None:
    """Snapshot capture blobs into the evidence store for a finding."""
    settings = _settings()
    store = CaptureStore(settings.traffic_capture_root)
    evidence = _open_evidence(settings, store)
    try:
        digests = evidence.snapshot_for_finding(sha, finding_id)
    finally:
        evidence.close()
    for digest in digests:
        typer.echo(digest)


@traffic_app.command("release")
def release(
    sha: Annotated[str, typer.Option("--sha", help="Evidence blob digest to release")],
) -> None:
    """Release a quarantined evidence artifact into the retention lifecycle."""
    settings = _settings()
    store = CaptureStore(settings.traffic_capture_root)
    evidence = _open_evidence(settings, store)
    try:
        released = evidence.release_from_quarantine(sha)
    finally:
        evidence.close()
    typer.echo(f"released={released} {sha}")


@traffic_app.command("reclaim")
def reclaim(
    max_bytes: Annotated[
        int | None,
        typer.Option(
            "--max-bytes",
            help="Threshold in bytes; defaults to QUARRY_TRAFFIC_CAPTURE_MAX_BYTES",
        ),
    ] = None,
) -> None:
    """Delete unreferenced capture blobs once the store exceeds the threshold."""
    settings = _settings()
    threshold = settings.traffic_capture_max_bytes if max_bytes is None else max_bytes
    store = CaptureStore(settings.traffic_capture_root)
    index = _open_index(settings)
    evidence = _open_evidence(settings, store)
    try:
        report = store.reclaim(
            index,
            threshold,
            referenced=evidence.referenced_capture_digests(),
            lock=evidence.snapshot_lock,
        )
    finally:
        evidence.close()
        index.close()
    state = "skipped (snapshot in progress)" if report.skipped else "completed"
    typer.echo(
        f"reclaim {state}: deleted {report.deleted_blobs} blob(s), "
        f"{report.deleted_rows} row(s); {report.bytes_before} -> {report.bytes_after} bytes"
    )
