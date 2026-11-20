"""Canonical, text-safe serialization of a captured HTTP exchange.

Every capture blob and every evidence blob is produced by
:func:`serialize_exchange`, so the two stores share one wire format:

* request line, one line per request header, then the request body;
* response status line, one line per response header, then the response body.

The format is text-safe by construction: a body that decodes as UTF-8 is stored
inline, a body that does not is stored base64-encoded behind a
``*-body-base64`` marker. That is what lets ``Scrubber.scrub(text)`` operate on
the complete serialized exchange without a bytes-aware redaction path.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field


def _empty_headers() -> tuple[tuple[str, str], ...]:
    return ()


@dataclass(frozen=True)
class CapturedExchange:
    """One request/response pair as observed by the recording proxy.

    Header order is preserved: byte-identical exchanges must serialize
    byte-identically for content-addressing to dedup as expected.
    """

    method: str
    url: str
    status_code: int
    request_headers: tuple[tuple[str, str], ...] = field(default_factory=_empty_headers)
    request_body: bytes | None = None
    response_headers: tuple[tuple[str, str], ...] = field(default_factory=_empty_headers)
    response_body: bytes | None = None
    reason: str = ""


def _body_lines(prefix: str, body: bytes | None) -> list[str]:
    if not body:
        return [f"{prefix}: 0 bytes"]
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        encoded = base64.b64encode(body).decode("ascii")
        return [f"{prefix}-base64: {len(body)} bytes", encoded]
    return [f"{prefix}: {len(body)} bytes", text]


def serialize_exchange(exchange: CapturedExchange) -> bytes:
    """Serialize *exchange* to the canonical text-safe byte format."""
    lines = [f"request: {exchange.method} {exchange.url} HTTP/1.1"]
    lines.extend(f"request-header: {name}: {value}" for name, value in exchange.request_headers)
    lines.extend(_body_lines("request-body", exchange.request_body))

    status_line = f"response: {exchange.status_code}"
    if exchange.reason:
        status_line = f"{status_line} {exchange.reason}"
    lines.append(status_line)
    lines.extend(f"response-header: {name}: {value}" for name, value in exchange.response_headers)
    lines.extend(_body_lines("response-body", exchange.response_body))

    return ("\n".join(lines) + "\n").encode("utf-8")
