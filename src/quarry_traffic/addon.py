"""mitmproxy addon mounted by the recording-proxy sidecar.

``mitmdump -s addon.py`` imports this module and registers the ``addons`` list
below. Each HTTP response is recorded through
:class:`quarry_traffic.recorder.CaptureRecorder` and then passed through
unmodified; a capture failure is logged and never breaks forwarding.

The capture root comes from ``QUARRY_TRAFFIC_CAPTURE_ROOT`` (the compose stack
mounts the shared traffic-capture volume there). This module deliberately imports
only the stdlib-only capture modules so the proxy container needs nothing from
the rest of the Quarry package tree.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from quarry_traffic.capture_index import CaptureIndex, capture_index_path
from quarry_traffic.capture_store import CaptureStore
from quarry_traffic.recorder import CaptureRecorder
from quarry_traffic.serialize import CapturedExchange

logger = logging.getLogger(__name__)

DEFAULT_CAPTURE_ROOT = ".quarry/traffic-capture"


def _headers(flow: Any, *, request: bool) -> tuple[tuple[str, str], ...]:
    message = flow.request if request else flow.response
    items = message.headers.items(multi=True)
    return tuple((str(name), str(value)) for name, value in items)


def _body(flow: Any, *, request: bool) -> bytes | None:
    message = flow.request if request else flow.response
    content = message.get_content(strict=False)
    return content if isinstance(content, bytes) else None


def exchange_from_flow(flow: Any) -> CapturedExchange:
    """Build the serializable exchange from a mitmproxy HTTPFlow."""
    response = flow.response
    return CapturedExchange(
        method=str(flow.request.method),
        url=str(flow.request.pretty_url),
        status_code=int(response.status_code),
        request_headers=_headers(flow, request=True),
        request_body=_body(flow, request=True),
        response_headers=_headers(flow, request=False),
        response_body=_body(flow, request=False),
        reason=str(response.reason or ""),
    )


class RecordingAddon:
    """Record every HTTP response into the content-addressed capture store."""

    def __init__(self, capture_root: Path | str) -> None:
        self.capture_root = Path(capture_root)
        self.store = CaptureStore(self.capture_root)
        self.index = CaptureIndex(capture_index_path(self.capture_root))
        self.recorder = CaptureRecorder(self.store, self.index)

    def response(self, flow: Any) -> None:
        if flow.response is None:
            return
        try:
            self.recorder.record(exchange_from_flow(flow))
        except Exception:
            # Fail open: the proxy must keep forwarding even if capture fails.
            logger.exception(
                "failed to record exchange %s", getattr(flow.request, "pretty_url", "?")
            )

    def done(self) -> None:
        self.index.close()


def _addon_from_env() -> RecordingAddon:
    return RecordingAddon(os.environ.get("QUARRY_TRAFFIC_CAPTURE_ROOT", DEFAULT_CAPTURE_ROOT))


addons = [_addon_from_env()]
