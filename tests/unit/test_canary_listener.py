"""Unit tests for the SSRF/XXE canary listener (Tier 1 in-process + shared parsing).

Pins the listener contract from openspec change canary-callback-listener:
  - Tier-1 loopback bind on an ephemeral port; non-loopback bind fails closed.
  - Every request is logged as one CanaryCallback (method/path/source_ip/timestamp).
  - Request headers and body are NEVER captured; the path is length-capped.
  - The response body is a fixed JSON token echo (no request-content reflection).
  - The listener self-terminates after its TTL.
  - QUARRY_CANARY_URL is set to the tier-specific bound address.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
import urllib.request
from collections.abc import Iterator

import pytest

from quarry.egress import EgressPolicyError
from quarry.schemas import CANARY_PATH_MAX_CHARS, CanaryCallback
from quarry_activities import sandbox_exec as se
from quarry_activities.sandbox import LocalSubprocessSandbox

_TOKEN = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def local_listener() -> Iterator[tuple[int, se.CanaryStop]]:
    """A running Tier-1 canary listener; stopped on teardown."""
    port, stop = se._start_canary_local(_TOKEN)
    try:
        yield port, stop
    finally:
        stop()


def _get(url: str, *, headers: dict[str, str] | None = None, data: bytes | None = None):
    req = urllib.request.Request(url, headers=headers or {}, data=data)
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (loopback only)
        return resp.status, resp.read().decode("utf-8")


class TestTier1Listener:
    def test_start_returns_ephemeral_port(self, local_listener: tuple[int, se.CanaryStop]) -> None:
        port, _stop = local_listener
        assert isinstance(port, int)
        assert port > 0

    def test_request_is_logged_with_safe_fields(
        self, local_listener: tuple[int, se.CanaryStop]
    ) -> None:
        port, stop = local_listener
        status, body = _get(f"http://127.0.0.1:{port}/{_TOKEN}")
        assert status == 200
        assert json.loads(body) == {"token": _TOKEN}

        callbacks = stop()
        assert len(callbacks) == 1
        cb = callbacks[0]
        assert isinstance(cb, CanaryCallback)
        assert cb.method == "GET"
        assert _TOKEN in cb.path
        assert cb.source_ip == "127.0.0.1"
        assert cb.timestamp  # ISO-8601 string, non-empty

    def test_response_does_not_reflect_request_content(
        self, local_listener: tuple[int, se.CanaryStop]
    ) -> None:
        port, _stop = local_listener
        status, body = _get(
            f"http://127.0.0.1:{port}/{_TOKEN}?probe=abc",
            headers={"Authorization": "Bearer super-secret-value"},
            data=b"password=hunter2",
        )
        assert status == 200
        assert body == json.dumps({"token": _TOKEN})
        assert "super-secret-value" not in body
        assert "hunter2" not in body

    def test_headers_and_body_are_never_captured(
        self, local_listener: tuple[int, se.CanaryStop]
    ) -> None:
        port, stop = local_listener
        _get(
            f"http://127.0.0.1:{port}/{_TOKEN}",
            headers={"Authorization": "Bearer super-secret-value"},
            data=b"password=hunter2",
        )
        cb = stop()[0]
        dumped = cb.model_dump()
        assert set(dumped) == {"timestamp", "method", "path", "source_ip"}
        assert "super-secret-value" not in json.dumps(dumped)
        assert "hunter2" not in json.dumps(dumped)

    def test_long_path_is_capped(self, local_listener: tuple[int, se.CanaryStop]) -> None:
        port, stop = local_listener
        long_path = "/" + "a" * (CANARY_PATH_MAX_CHARS * 2)
        _get(f"http://127.0.0.1:{port}{long_path}")
        cb = stop()[0]
        assert len(cb.path) <= CANARY_PATH_MAX_CHARS

    def test_non_loopback_bind_fails_closed(self) -> None:
        with pytest.raises(EgressPolicyError):
            se._start_canary_local(_TOKEN, bind_host="0.0.0.0")

    def test_ttl_timer_uses_configured_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        class _SpyTimer:
            def __init__(self, interval: float, function: object) -> None:
                captured["interval"] = interval
                captured["function"] = function
                self.daemon = False

            def start(self) -> None:
                captured["started"] = True

            def cancel(self) -> None:
                captured["cancelled"] = True

        monkeypatch.setattr(se.threading, "Timer", _SpyTimer)
        _port, stop = se._start_canary_local(_TOKEN)
        try:
            assert captured["interval"] == se.CANARY_TTL_SECONDS
            assert captured["started"] is True
        finally:
            stop()
        assert captured["cancelled"] is True


class TestCanaryUrlInjection:
    def test_local_tier_sets_quarry_canary_url(self) -> None:
        source, env = se._start_canary_listener(LocalSubprocessSandbox(), _TOKEN)
        try:
            url = env[se.CANARY_URL_ENV]
            assert url.startswith("http://127.0.0.1:")
            assert url.endswith(f"/{_TOKEN}")
        finally:
            se._collect_canary_logs(source)

    def test_url_reaches_the_listener(self) -> None:
        source, env = se._start_canary_listener(LocalSubprocessSandbox(), _TOKEN)
        status, body = _get(env[se.CANARY_URL_ENV])
        callbacks = se._collect_canary_logs(source)
        assert status == 200
        assert json.loads(body) == {"token": _TOKEN}
        assert len(callbacks) == 1
        assert _TOKEN in callbacks[0].path


class TestCanaryLogParsing:
    def test_parses_json_lines_only(self) -> None:
        log = "\n".join(
            [
                "starting listener",
                json.dumps(
                    {
                        "timestamp": "2026-01-01T00:00:00+00:00",
                        "method": "GET",
                        "path": f"/{_TOKEN}",
                        "source_ip": "10.0.0.5",
                    }
                ),
                "not json",
                "",
            ]
        )
        callbacks = se._parse_canary_logs(log)
        assert len(callbacks) == 1
        assert callbacks[0].source_ip == "10.0.0.5"
        assert callbacks[0].method == "GET"

    def test_extra_log_fields_are_ignored(self) -> None:
        """A log line carrying headers must not leak them into the callback."""
        log = json.dumps(
            {
                "timestamp": "t",
                "method": "POST",
                "path": f"/{_TOKEN}",
                "source_ip": "10.0.0.9",
                "headers": {"Authorization": "Bearer leak"},
                "body": "password=hunter2",
            }
        )
        callbacks = se._parse_canary_logs(log)
        assert len(callbacks) == 1
        assert set(callbacks[0].model_dump()) == {"timestamp", "method", "path", "source_ip"}

    def test_empty_log_yields_no_callbacks(self) -> None:
        assert se._parse_canary_logs("") == []


class TestListenerScript:
    def test_script_does_not_log_headers_or_body(self) -> None:
        script = se._canary_listener_script()
        # The script must read the body only to drain it, never to store it.
        assert "headers" in script  # Content-Length read for draining
        assert "Authorization" not in script
        # Fixed response body is the token echo.
        assert '{"token"' in script
