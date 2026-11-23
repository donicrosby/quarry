"""Recording proxy addon and the recorder that owns its write path.

:class:`CaptureRecorder` is the whole capture pipeline minus mitmproxy: it
serializes an exchange, writes the content-addressed blob, normalizes the URL,
and inserts the index row. :mod:`quarry_traffic.addon` wraps it in a mitmproxy
addon, which keeps the pipeline unit-testable without a proxy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

from quarry_traffic.capture_index import CaptureIndex
from quarry_traffic.capture_store import CaptureStore
from quarry_traffic.normalize import normalize_url_template
from quarry_traffic.serialize import CapturedExchange, serialize_exchange


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with millisecond precision."""
    return datetime.now(UTC).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class RecordedExchange:
    """Result of recording one exchange into the capture store."""

    sha256: str
    row_id: int
    url_template: str


class CaptureRecorder:
    """Serialize, store, normalize, and index one exchange at a time."""

    def __init__(self, store: CaptureStore, index: CaptureIndex) -> None:
        self.store = store
        self.index = index

    def record(
        self, exchange: CapturedExchange, *, timestamp: str | None = None
    ) -> RecordedExchange:
        data = serialize_exchange(exchange)
        digest = self.store.write_blob(data)
        url_template = normalize_url_template(exchange.url)
        host = urlsplit(exchange.url).netloc
        row_id = self.index.add_exchange(
            host=host,
            sha256=digest,
            url_template=url_template,
            method=exchange.method,
            status_code=exchange.status_code,
            timestamp=timestamp or utc_now_iso(),
            byte_count=len(data),
        )
        return RecordedExchange(sha256=digest, row_id=row_id, url_template=url_template)
