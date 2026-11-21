"""URL template normalization for the capture index.

Captured exchange URLs are stored in two forms: the exact URL on the exchange
record and a normalized template used for dedup/pagination queries. Path
segments and query values matching one of four parameter classes are replaced
with typed placeholders:

===============  ===============  =============
class            placeholder      example
===============  ===============  =============
UUID             ``{uuid}``       ``550e8400-e29b-41d4-a716-446655440000``
integer id       ``{id}``         ``42``
base64 token     ``{token}``      ``eyJhbGciOiJIUzI1NiJ9``
ISO date         ``{date}``       ``2026-11-18``
===============  ===============  =============

The parameter set is deliberately conservative: a false negative (two requests
recorded under distinct templates) is safer than a false positive (two distinct
resources collapsed into one template).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_INTEGER = re.compile(r"^\d+$")
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Base64 and base64url alphabets; a minimum length keeps ordinary hyphenated
# slugs and short words from collapsing into {token}.
_BASE64_TOKEN = re.compile(r"^[A-Za-z0-9+/=_-]{20,}$")


def normalize_segment(segment: str) -> str:
    """Return the placeholder for *segment*, or *segment* unchanged."""
    if not segment:
        return segment
    if _UUID.fullmatch(segment):
        return "{uuid}"
    if _ISO_DATE.fullmatch(segment):
        return "{date}"
    if _INTEGER.fullmatch(segment):
        return "{id}"
    if _BASE64_TOKEN.fullmatch(segment):
        return "{token}"
    return segment


def normalize_query(query: str) -> str:
    """Normalize query parameter values while preserving parameter names/order."""
    if not query:
        return query
    normalized: list[str] = []
    for part in query.split("&"):
        if not part:
            normalized.append(part)
            continue
        name, sep, value = part.partition("=")
        if not sep:
            normalized.append(part)
            continue
        normalized.append(f"{name}={normalize_segment(value)}")
    return "&".join(normalized)


def normalize_url_template(url: str) -> str:
    """Return the normalized URL template for *url*.

    The scheme, netloc, and fragment are preserved; path segments and query
    values are normalized. A URL without a scheme (a bare path) is normalized
    as a path.
    """
    parts = urlsplit(url)
    path = "/".join(normalize_segment(segment) for segment in parts.path.split("/"))
    query = normalize_query(parts.query)
    return urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))
