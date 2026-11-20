"""Recording traffic-capture proxy and verified evidence store.

Two content-addressed stores with different lifetimes:

* the disposable full-capture store the mitmproxy sidecar writes every agent
  HTTP exchange into (``blobs/<sha>.bin``), queried through
  :class:`~quarry_traffic.capture_index.CaptureIndex`;
* the durable evidence store a finding binding snapshots redacted capture blobs
  into (``blobs/<2hex>/<sha>.bin``), with staged writes, verify-on-read, and a
  writer lock that keeps reclamation from racing a snapshot —
  :class:`~quarry_traffic.evidence.EvidenceStore`.

This package's ``__init__`` imports only the stdlib-only capture modules so the
mitmproxy sidecar can mount ``src/`` and import the addon without the rest of
the Quarry dependency tree. Import :mod:`quarry_traffic.evidence` explicitly
where the evidence store is needed.
"""

from __future__ import annotations

from quarry_traffic.capture_index import CaptureIndex, CaptureRow, capture_index_path
from quarry_traffic.capture_store import CaptureStore, ReclaimReport
from quarry_traffic.locks import SnapshotLock
from quarry_traffic.normalize import normalize_url_template
from quarry_traffic.recorder import CaptureRecorder, RecordedExchange, utc_now_iso
from quarry_traffic.serialize import CapturedExchange, serialize_exchange

__all__ = [
    "CaptureIndex",
    "CaptureRecorder",
    "CaptureRow",
    "CaptureStore",
    "CapturedExchange",
    "ReclaimReport",
    "RecordedExchange",
    "SnapshotLock",
    "capture_index_path",
    "normalize_url_template",
    "serialize_exchange",
    "utc_now_iso",
]
