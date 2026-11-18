"""Scrub-invariant tests for the canary listener's captured evidence.

The canary listener is attacker-reachable: a crafted request may carry
credentials in its headers or body.  The listener must capture ONLY
method/path/source_ip/timestamp — never headers or body — so credential-like
material can never reach the prove prompt through canary evidence.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
import urllib.request

import pytest

from quarry_activities import sandbox_exec as se

_TOKEN = "0123456789abcdef0123456789abcdef"
_CREDENTIALS = {
    "Authorization": "Bearer sk-live-DEADBEEFDEADBEEF",
    "Cookie": "session=secret-session-cookie",
    "X-Api-Key": "AKIAIOSFODNN7EXAMPLE",
}
_CREDENTIAL_BODY = b'{"password": "hunter2", "api_key": "sk-secret-body-key"}'

_CREDENTIAL_MARKERS = (
    "sk-live-DEADBEEFDEADBEEF",
    "secret-session-cookie",
    "AKIAIOSFODNN7EXAMPLE",
    "hunter2",
    "sk-secret-body-key",
)


@pytest.fixture
def captured() -> list[dict[str, object]]:
    """Fire a credential-bearing request at a fresh listener; return captures."""
    port, stop = se._start_canary_local(_TOKEN)
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/{_TOKEN}?redirect=http://evil.example/",
            headers=_CREDENTIALS,
            data=_CREDENTIAL_BODY,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (loopback)
            assert resp.status == 200
        return [cb.model_dump() for cb in stop()]
    finally:
        stop()


class TestCanaryScrub:
    def test_only_safe_fields_are_captured(self, captured: list[dict[str, object]]) -> None:
        assert len(captured) == 1
        assert set(captured[0]) == {"timestamp", "method", "path", "source_ip"}

    def test_no_credential_marker_in_captures(self, captured: list[dict[str, object]]) -> None:
        blob = json.dumps(captured)
        for marker in _CREDENTIAL_MARKERS:
            assert marker not in blob, f"credential marker leaked into canary log: {marker}"

    def test_no_header_or_body_keys_present(self, captured: list[dict[str, object]]) -> None:
        keys = set(captured[0])
        assert "headers" not in keys
        assert "body" not in keys
        assert "body_truncated" not in keys
